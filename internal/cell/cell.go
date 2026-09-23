package cell

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type Cell struct {
	Root     string
	ReadOnly bool
}

func New(root string, readOnly bool) (*Cell, error) {
	if root == "" {
		return nil, errors.New("cell: root filesystem path is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("cell: resolving root: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("cell: cannot access root filesystem %s: %w", abs, err)
	}
	real = filepath.Clean(real)
	info, err := os.Stat(real)
	if err != nil {
		return nil, fmt.Errorf("cell: cannot access root filesystem %s: %w", real, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("cell: root filesystem %s is not a directory", real)
	}
	if real == "/" {
		return nil, errors.New("cell: refusing to use host / as the Jail root filesystem")
	}
	return &Cell{Root: real, ReadOnly: readOnly}, nil
}

func (c *Cell) ShellPath() string {
	return filepath.Join(c.Root, "bin", "sh")
}

func (c *Cell) ShellExists() bool {
	info, err := os.Stat(c.ShellPath())
	return err == nil && !info.IsDir()
}

func (c *Cell) Validate() error {
	if !c.ShellExists() {
		return fmt.Errorf("cell: root filesystem %s has no /bin/sh", c.Root)
	}
	loader := filepath.Join(c.Root, "lib64", "ld-linux-x86-64.so.2")
	if _, err := os.Stat(loader); err != nil {
		return fmt.Errorf("cell: root filesystem %s is missing the dynamic loader", c.Root)
	}
	return nil
}

func (c *Cell) Cleanup() error {
	if c == nil || c.Root == "" {
		return nil
	}
	if c.Root == "/" {
		return errors.New("cell: refusing to touch host root")
	}
	return nil
}

func ValidateRootfsNotEscape(root string) error {
	if root == "" {
		return errors.New("cell: root filesystem path is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("cell: resolving root: %w", err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("cell: resolve %s: %w", abs, err)
	}
	real = filepath.Clean(real)
	if real == "/" {
		return errors.New("cell: refusing to use host / as the Jail root filesystem")
	}
	info, err := os.Stat(real)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("cell: %s is not a directory", real)
	}
	return nil
}
