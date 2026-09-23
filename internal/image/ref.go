package image

import (
	"fmt"
	"regexp"
	"strings"

	"jailor/internal/store"
)

var nameTagRe = regexp.MustCompile(`^[a-z0-9]+((\.|_|-+)[a-z0-9]+)*(/[a-z0-9]+((\.|_|-+)[a-z0-9]+)*)*$`)
var tagRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`)

type Ref struct {
	Registry string
	Name     string
	Tag      string
	Digest   store.Digest
}

func ParseRef(s string) (Ref, error) {
	if s == "" {
		return Ref{}, fmt.Errorf("image: empty reference")
	}
	orig := s
	dig := store.Digest{}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		parsed, err := store.ParseDigest(s[i+1:])
		if err != nil {
			return Ref{}, fmt.Errorf("image: reference %q: %w", orig, err)
		}
		dig = parsed
		s = s[:i]
	}
	tag := ""
	if i := indexOfTagSep(s); i >= 0 {
		t := s[i+1:]
		if !tagRe.MatchString(t) {
			return Ref{}, fmt.Errorf("image: reference %q has invalid tag %q", orig, t)
		}
		tag = t
		s = s[:i]
	}

	var reg, name string
	first := strings.SplitN(s, "/", 2)
	if len(first) == 2 && (strings.Contains(first[0], ".") || strings.Contains(first[0], ":") || first[0] == "localhost") {
		reg = first[0]
		name = first[1]
	} else {
		name = s
	}

	if name == "" {
		return Ref{}, fmt.Errorf("image: reference %q has no repository name", orig)
	}
	if !nameTagRe.MatchString(name) {
		return Ref{}, fmt.Errorf("image: reference %q has invalid repository name %q", orig, name)
	}
	if tag == "" && dig.Hex == "" {
		tag = "latest"
	}

	return Ref{Registry: reg, Name: name, Tag: tag, Digest: dig}, nil
}

func indexOfTagSep(s string) int {
	lastSlash := strings.LastIndexByte(s, '/')
	lastColon := strings.LastIndexByte(s, ':')
	if lastColon < 0 {
		return -1
	}
	if lastColon > lastSlash {
		return lastColon
	}
	return -1
}

func (r Ref) String() string {
	if r.Registry != "" {
		if r.Digest.Valid() {
			return r.Registry + "/" + r.Name + "@" + r.Digest.String()
		}
		t := r.Tag
		if t == "" {
			t = "latest"
		}
		return r.Registry + "/" + r.Name + ":" + t
	}
	if r.Digest.Valid() {
		return r.Name + "@" + r.Digest.String()
	}
	t := r.Tag
	if t == "" {
		t = "latest"
	}
	return r.Name + ":" + t
}

func (r Ref) LocalName() string {
	if r.Digest.Valid() {
		return r.Name + "@" + r.Digest.String()
	}
	t := r.Tag
	if t == "" {
		t = "latest"
	}
	return r.Name + ":" + t
}

func (r Ref) MatchesTag() bool { return r.Digest.Hex == "" }

func (r Ref) Repository() string {
	if r.Registry == "" {
		return r.Name
	}
	return r.Registry + "/" + r.Name
}
