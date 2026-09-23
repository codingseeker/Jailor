package registry

import (
	"errors"
	"testing"
)

func pushClient() *Client {
	c := New()
	c.MaxConcurrent = 2
	c.Retries = 3
	return c
}

func TestPushRoundTrip(t *testing.T) {

	src := newMockRegistry(t, twoLayerImage())
	is := openTestStore(t)
	if _, err := pullClient(t).Pull(is, src.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatal(err)
	}

	dst := newMockRegistry(t, buildTestImage("v1", nil))
	res, err := pushClient().Push(is, dst.addr()+"/team/app:v1", PushOptions{})
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if res.BlobsUploaded != 3 {
		t.Errorf("blobs uploaded = %d, want 3 (config + 2 layers)", res.BlobsUploaded)
	}
	if res.BlobsSkipped != 0 {
		t.Errorf("blobs skipped = %d, want 0", res.BlobsSkipped)
	}

	img := twoLayerImage()
	if _, ok := dst.pushedBlobs[img.ManifestDigest]; ok {
		t.Error("push uploaded the manifest as a blob")
	}
	if dst.pushedManifests["team/app:v1"] == "" {
		t.Error("manifest not recorded under team/app:v1")
	}
	got, ok := dst.pushedBlobs[img.layerDigest(0)]
	if !ok || testDigest(got) != img.layerDigest(0) {
		t.Errorf("layer 0 not uploaded correctly")
	}
	got, ok = dst.pushedBlobs[img.layerDigest(1)]
	if !ok || testDigest(got) != img.layerDigest(1) {
		t.Errorf("layer 1 not uploaded correctly")
	}
}

func TestPushSkipsExistingBlobs(t *testing.T) {
	src := newMockRegistry(t, twoLayerImage())
	is := openTestStore(t)
	if _, err := pullClient(t).Pull(is, src.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatal(err)
	}

	dst := newMockRegistry(t, twoLayerImage())
	c := pushClient()
	if _, err := c.Push(is, dst.addr()+"/team/app:v1", PushOptions{}); err != nil {
		t.Fatal(err)
	}
	res, err := c.Push(is, dst.addr()+"/team/app:v1", PushOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.BlobsUploaded != 0 {
		t.Errorf("second push uploaded %d blobs, want 0", res.BlobsUploaded)
	}
	if res.BlobsSkipped != 3 {
		t.Errorf("second push skipped %d blobs, want 3", res.BlobsSkipped)
	}
}

func TestPushMissingLocalImage(t *testing.T) {
	is := openTestStore(t)
	dst := newMockRegistry(t, twoLayerImage())
	if _, err := pushClient().Push(is, dst.addr()+"/team/app:v1", PushOptions{}); err == nil {
		t.Fatal("push of an image that is not stored should fail")
	}
}

func TestPushDeniedWrites(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.requireAuth = true
	m.rejectPushAuth = true
	is := openTestStore(t)

	src := newMockRegistry(t, img)
	if _, err := pullClient(t).Pull(is, src.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatal(err)
	}

	c := pushClient()
	c.Creds = func(host string) Credential {
		return Credential{Username: "alice", Password: "s3cret"}
	}
	if _, err := c.Push(is, m.addr()+"/team/app:v1", PushOptions{}); err == nil {
		t.Fatal("push to a registry denying writes should fail")
	}
}

func TestPushRequiresAuth(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.requireAuth = true
	m.tokenAuthRequired = true
	is := openTestStore(t)

	src := newMockRegistry(t, img)
	if _, err := pullClient(t).Pull(is, src.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := pushClient().Push(is, m.addr()+"/team/app:v1", PushOptions{}); err == nil {
		t.Fatal("anonymous push to an authenticated registry should fail")
	} else if !errors.Is(err, ErrAuthRequired) {
		t.Errorf("want ErrAuthRequired, got %v", err)
	}
}

func TestPushWithAuth(t *testing.T) {
	img := twoLayerImage()
	m := newMockRegistry(t, img)
	m.requireAuth = true
	m.tokenAuthRequired = true
	m.tokenUser = "alice"
	m.tokenPass = "s3cret"
	is := openTestStore(t)

	src := newMockRegistry(t, img)
	if _, err := pullClient(t).Pull(is, src.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatal(err)
	}
	c := pushClient()
	c.Creds = func(host string) Credential {
		return Credential{Username: "alice", Password: "s3cret"}
	}
	if _, err := c.Push(is, m.addr()+"/team/app:v1", PushOptions{}); err != nil {
		t.Fatalf("authenticated push: %v", err)
	}
	if m.pushedManifests["team/app:v1"] == "" {
		t.Error("manifest not recorded for authenticated push")
	}
}

func TestPushByDigestReference(t *testing.T) {
	img := twoLayerImage()
	src := newMockRegistry(t, img)
	is := openTestStore(t)
	if _, err := pullClient(t).Pull(is, src.addr()+"/team/app:v1", PullOptions{}); err != nil {
		t.Fatal(err)
	}
	dst := newMockRegistry(t, img)
	if _, err := pushClient().Push(is, dst.addr()+"/team/app@"+img.ManifestDigest, PushOptions{}); err == nil {
		t.Fatal("push by digest should be rejected")
	}
}
