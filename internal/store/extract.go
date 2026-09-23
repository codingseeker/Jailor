package store

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func (s *Store) extractTo(d Digest, destDir string) error {
	f, err := os.Open(s.BlobPath(d))
	if err != nil {
		return fmt.Errorf("store: open layer blob %s: %w", d, err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("store: layer %s is not a valid gzip stream: %w", d, err)
	}
	defer gz.Close()

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("store: mkdir layer tree: %w", err)
	}
	if err := extractTar(gz, destDir); err != nil {
		return fmt.Errorf("store: extract layer %s: %w", d, err)
	}
	return nil
}

func extractTar(r io.Reader, destDir string) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		}
		target, err := secureJoin(destDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)&0o777|0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := writeFile(target, tr, os.FileMode(hdr.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		case tar.TypeLink:
			linkTarget, err := secureJoin(destDir, hdr.Linkname)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.Remove(target)
			if err := os.Link(linkTarget, target); err != nil {
				return err
			}
		default:

			continue
		}
	}
}

func writeFile(target string, r io.Reader, mode os.FileMode) error {
	_ = os.Remove(target)
	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode|0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func secureJoin(root, name string) (string, error) {
	if name == "" {
		return "", errors.New("store: empty archive member name")
	}
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return "", fmt.Errorf("store: refusing absolute archive member %q", name)
	}
	clean := filepath.Clean(filepath.FromSlash(name))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("store: refusing archive member escaping root: %q", name)
	}
	target := filepath.Join(root, clean)
	if !within(root, target) {
		return "", fmt.Errorf("store: archive member %q escapes root", name)
	}

	if err := checkAncestors(root, filepath.Dir(target)); err != nil {
		return "", err
	}
	return target, nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != "..")
}

func checkAncestors(root, dir string) error {
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return err
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		info, err := os.Lstat(cur)
		if err != nil {
			break
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(cur)
			if err != nil {
				return fmt.Errorf("store: cannot resolve symlink %s: %w", cur, err)
			}
			if !within(root, resolved) {
				return fmt.Errorf("store: archive member escapes through symlink %s", cur)
			}
		}
	}
	return nil
}
