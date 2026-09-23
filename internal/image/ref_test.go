package image

import (
	"strings"
	"testing"
)

func TestParseRef(t *testing.T) {
	cases := []struct {
		in       string
		registry string
		name     string
		tag      string
		want     string
	}{
		{"alpine", "", "alpine", "latest", "alpine:latest"},
		{"alpine:edge", "", "alpine", "edge", "alpine:edge"},
		{"library/alpine", "", "library/alpine", "latest", "library/alpine:latest"},
		{"localhost:5000/team/app", "localhost:5000", "team/app", "latest", "localhost:5000/team/app:latest"},
		{"registry.example.com/app:9", "registry.example.com", "app", "9", "registry.example.com/app:9"},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if err != nil {
			t.Fatalf("ParseRef(%q): %v", c.in, err)
		}
		if r.Registry != c.registry || r.Name != c.name || r.Tag != c.tag {
			t.Errorf("ParseRef(%q) = {%q %q %q}", c.in, r.Registry, r.Name, r.Tag)
		}
		if got := r.String(); got != c.want {
			t.Errorf("ParseRef(%q).String() = %q, want %q", c.in, got, c.want)
		}
	}

	r, err := ParseRef("alpine@sha256:" + strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Digest.Valid() || r.Tag != "" {
		t.Fatalf("digest reference parsed incorrectly: %+v", r)
	}
	if got := r.String(); got != "alpine@sha256:"+strings.Repeat("a", 64) {
		t.Errorf("digest String() = %q", got)
	}
	if r.MatchesTag() {
		t.Error("digest pin should not be tag-matched")
	}

	for _, bad := range []string{"", "ALPINE", "a b", "a:b:c", "-bad:tag", "repo/invalid_tag!"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("ParseRef(%q) should fail", bad)
		}
	}
}

func TestRefMatching(t *testing.T) {
	r, _ := ParseRef("busybox:1.35")
	if !r.MatchesTag() {
		t.Error("tag reference should be tag-matched")
	}
	if r.String() != "busybox:1.35" || r.LocalName() != "busybox:1.35" {
		t.Errorf("busybox String/LocalName = %q/%q", r.String(), r.LocalName())
	}
	r2, _ := ParseRef("localhost:5000/team/app:v2")
	if r2.Repository() != "localhost:5000/team/app" {
		t.Errorf("Repository = %q", r2.Repository())
	}
	r3, _ := ParseRef("alpine")
	if r3.String() != "alpine:latest" {
		t.Errorf("default tag = %q", r3.String())
	}
}
