package image

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"jailor/internal/store"
)

const SubDir = "store"
const refsFile = "images.json"

type Image struct {
	Name         string
	Digest       store.Digest
	Layers       []store.Digest
	Config       ImageConfig
	Manifest     Manifest
	Created      time.Time
	Size         int64
	Architecture string
	OS           string
}

type refRow struct {
	Manifest store.Digest `json:"manifest"`
	Created  time.Time    `json:"created"`
}

type refsDoc struct {
	Images map[string]refRow `json:"images"`
}
type ImageStore struct {
	st *store.Store

	refsPath string

	mu sync.Mutex
}

func Open(root string) (*ImageStore, error) {
	if root == "" {
		return nil, fmt.Errorf("image: no root specified")
	}
	st, err := store.Open(filepath.Join(root, SubDir))
	if err != nil {
		return nil, err
	}
	is := &ImageStore{st: st, refsPath: filepath.Join(st.MetaDir(), refsFile)}
	if err := is.loadRefs(); err != nil {
		return nil, err
	}
	return is, nil
}

func (is *ImageStore) Store() *store.Store { return is.st }

func (is *ImageStore) loadRefs() error {
	data, err := os.ReadFile(is.refsPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("image: read tags: %w", err)
	}
	var doc refsDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("image: parse tags: %w", err)
	}
	if doc.Images == nil {
		doc.Images = map[string]refRow{}
	}
	return nil
}

func (is *ImageStore) saveRefs(doc refsDoc) error {
	if doc.Images == nil {
		doc.Images = map[string]refRow{}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("image: encode tags: %w", err)
	}
	return store.AtomicWrite(is.refsPath, data, 0o600)
}

func (is *ImageStore) readDoc() (refsDoc, error) {
	var doc refsDoc
	data, err := os.ReadFile(is.refsPath)
	if os.IsNotExist(err) {
		doc.Images = map[string]refRow{}
		return doc, nil
	}
	if err != nil {
		return doc, err
	}
	err = json.Unmarshal(data, &doc)
	if doc.Images == nil {
		doc.Images = map[string]refRow{}
	}
	return doc, err
}

func (is *ImageStore) resolveName(r Ref) (string, error) {
	if r.Digest.Valid() {
		return "", fmt.Errorf("image: %s is stored by digest; use a tag to address it locally", r.LocalName())
	}
	return r.LocalName(), nil
}

func (is *ImageStore) List() ([]Image, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	doc, err := is.readDoc()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(doc.Images))
	for n := range doc.Images {
		names = append(names, n)
	}
	sort.Strings(names)

	var out []Image
	for _, n := range names {
		img, err := is.get(rowDoc(doc, n))
		if err != nil {

			continue
		}
		img.Name = n
		out = append(out, *img)
	}
	return out, nil
}

func (is *ImageStore) Get(ref string) (*Image, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	r, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	name, err := is.resolveName(r)
	if err != nil {
		return nil, err
	}
	doc, err := is.readDoc()
	if err != nil {
		return nil, err
	}
	row, ok := doc.Images[name]
	if !ok {
		return nil, fmt.Errorf("image: no such image %s", name)
	}
	img, err := is.get(row)
	if err != nil {
		return nil, err
	}
	img.Name = name
	return img, nil
}

func rowDoc(doc refsDoc, name string) refRow { return doc.Images[name] }

func (is *ImageStore) get(row refRow) (*Image, error) {
	manData, err := is.st.OpenBlob(row.Manifest)
	if err != nil {
		return nil, fmt.Errorf("image: read manifest %s: %w", row.Manifest, err)
	}
	defer manData.Close()
	manBytes, err := readAll(manData)
	if err != nil {
		return nil, err
	}
	man, err := ParseManifest(manBytes)
	if err != nil {
		return nil, err
	}

	cfgData, err := is.st.OpenBlob(digestOf(man.Config))
	if err != nil {
		return nil, fmt.Errorf("image: read config %s: %w", digestOf(man.Config), err)
	}
	defer cfgData.Close()
	cfgBytes, err := readAll(cfgData)
	if err != nil {
		return nil, err
	}
	cfg, err := ParseImageConfig(cfgBytes)
	if err != nil {
		return nil, err
	}

	img := &Image{
		Digest:       row.Manifest,
		Manifest:     *man,
		Config:       *cfg,
		Architecture: cfg.Architecture,
		OS:           cfg.OS,
	}
	if cfg.Created != "" {
		if t, err := time.Parse(time.RFC3339Nano, cfg.Created); err == nil {
			img.Created = t
		}
	}
	size := man.Config.Size
	for i := range man.Layers {
		img.Layers = append(img.Layers, digestOf(man.Layers[i]))
		size += man.Layers[i].Size
	}
	img.Size = size
	return img, nil
}

func (is *ImageStore) Tag(source, target string) error {
	is.mu.Lock()
	defer is.mu.Unlock()

	src, err := ParseRef(source)
	if err != nil {
		return err
	}
	doc, err := is.readDoc()
	if err != nil {
		return err
	}
	var manifest store.Digest
	if src.Digest.Valid() {
		if !is.st.HasBlob(src.Digest) {
			return fmt.Errorf("image: manifest %s is not in the store", src.Digest)
		}
		if _, err := is.readManifest(src.Digest); err != nil {
			return err
		}
		manifest = src.Digest
	} else {
		row, ok := doc.Images[src.LocalName()]
		if !ok {
			return fmt.Errorf("image: no such image %s", src.LocalName())
		}
		manifest = row.Manifest
	}

	dst, err := ParseRef(target)
	if err != nil {
		return err
	}
	tname, err := is.resolveName(dst)
	if err != nil {
		return err
	}
	doc.Images[tname] = refRow{Manifest: manifest, Created: time.Now()}
	return is.saveRefs(doc)
}
func (is *ImageStore) Remove(ref string) error {
	is.mu.Lock()
	defer is.mu.Unlock()

	r, err := ParseRef(ref)
	if err != nil {
		return err
	}
	name, err := is.resolveName(r)
	if err != nil {
		return err
	}
	doc, err := is.readDoc()
	if err != nil {
		return err
	}
	row, ok := doc.Images[name]
	if !ok {
		return fmt.Errorf("image: no such image %s", name)
	}
	delete(doc.Images, name)
	if err := is.saveRefs(doc); err != nil {
		return err
	}
	return is.removeIfUnreferencedLocked(row.Manifest)
}

func (is *ImageStore) readManifest(d store.Digest) (*Manifest, error) {
	rc, err := is.st.OpenBlob(d)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	data, err := readAll(rc)
	if err != nil {
		return nil, err
	}
	return ParseManifest(data)
}

func (is *ImageStore) removeIfUnreferencedLocked(manDigest store.Digest) error {
	if is.referencedManifest(manDigest) {
		return nil
	}
	man, err := is.readManifest(manDigest)
	if err != nil {
		return nil
	}
	_ = is.st.RemoveBlob(manDigest)
	_ = is.st.RemoveBlob(digestOf(man.Config))
	for i := range man.Layers {
		d := digestOf(man.Layers[i])
		if is.layerReferencedByOther(manDigest, d) {
			continue
		}
		_ = is.st.RemoveBlob(d)
	}
	return nil
}

func (is *ImageStore) referencedManifest(d store.Digest) bool {
	doc, err := is.readDoc()
	if err == nil {
		for _, row := range doc.Images {
			if row.Manifest.String() == d.String() {
				return true
			}
		}
	}
	return is.containerUsesManifest(d)
}

func (is *ImageStore) layerReferencedByOther(exceptMan, layer store.Digest) bool {
	if is.containerUsesLayer(layer) {
		return true
	}
	doc, err := is.readDoc()
	if err != nil {
		return false
	}
	for _, row := range doc.Images {
		if row.Manifest.String() == exceptMan.String() {
			continue
		}
		man, err := is.readManifest(row.Manifest)
		if err != nil {
			continue
		}
		for i := range man.Layers {
			if digestOf(man.Layers[i]).String() == layer.String() {
				return true
			}
		}
	}
	return false
}

func (is *ImageStore) Inspect(ref string) (*Image, error) {
	return is.Get(ref)
}

func (is *ImageStore) Count() (int, error) {
	is.mu.Lock()
	defer is.mu.Unlock()
	doc, err := is.readDoc()
	if err != nil {
		return 0, err
	}
	return len(doc.Images), nil
}

type GarbageCollected struct {
	Blobs  int `json:"blobs"`
	Layers int `json:"layers"`
	Tags   int `json:"tags"`
}

func (is *ImageStore) GC() (GarbageCollected, error) {
	is.mu.Lock()
	defer is.mu.Unlock()

	var gc GarbageCollected

	referenced := map[string]bool{}
	doc, err := is.readDoc()
	if err != nil {
		return gc, err
	}
	for name, row := range doc.Images {
		man, err := is.readManifest(row.Manifest)
		if err != nil {

			delete(doc.Images, name)
			gc.Tags++
			continue
		}
		referenced[row.Manifest.String()] = true
		referenced[digestOf(man.Config).String()] = true
		for i := range man.Layers {
			referenced[digestOf(man.Layers[i]).String()] = true
		}
	}
	if gc.Tags > 0 {
		if err := is.saveRefs(doc); err != nil {
			return gc, err
		}
	}

	if err := is.walkContainers(func(_ string, meta containerMeta) error {
		referenced[meta.Manifest.String()] = true
		for _, d := range meta.Layers {
			referenced[d.String()] = true
		}
		return nil
	}); err != nil {
		return gc, err
	}

	layerDigests, err := is.st.LayerDigests()
	if err != nil {
		return gc, err
	}
	for _, d := range layerDigests {
		if !referenced[d.String()] {
			_ = is.st.RemoveBlob(d)
			gc.Layers++
			gc.Blobs++
		}
	}

	blobs, err := is.blobDigests()
	if err != nil {
		return gc, err
	}
	for _, d := range blobs {
		if referenced[d.String()] {
			continue
		}
		_ = is.st.RemoveBlob(d)
		gc.Blobs++
	}

	return gc, nil
}

func (is *ImageStore) blobDigests() ([]store.Digest, error) {
	var out []store.Digest
	root := is.st.BlobsDir()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		d, perr := store.ParseDigest("sha256:" + info.Name())
		if perr == nil && d.Valid() {
			out = append(out, d)
		}
		return nil
	})
	return out, err
}

func readAll(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
