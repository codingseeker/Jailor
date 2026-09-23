package oci

import (
	"encoding/json"
	"testing"

	"jailor/internal/config"
)

const benchBundleJSON = `{
	"ociVersion": "1.0",
	"process": {
		"args": ["/bin/sleep", "1"],
		"env": ["A=1", "B=2", "PATH=/usr/bin:/bin"],
		"cwd": "/",
		"noNewPrivileges": true,
		"capabilities": {"bounding": ["CAP_CHOWN","CAP_SETUID"],"effective": ["CAP_CHOWN","CAP_SETUID"]}
	},
	"root": {"readonly": true},
	"hostname": "bench",
	"linux": {
		"namespaces": [{"type":"pid"},{"type":"mount"},{"type":"network"}],
		"resources": {"memory":{"limit":268435456},"cpu":{"quota":50000,"period":100000},"pids":{"limit":100}},
		"seccomp": true
	},
	"jailor": {"network": "none", "userns": "auto"}
}`

func BenchmarkBundleTranslate(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var s Schema
		if err := json.Unmarshal([]byte(benchBundleJSON), &s); err != nil {
			b.Fatal(err)
		}
		if err := s.validate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExport(b *testing.B) {
	c := config.Default()
	c.Command = []string{"/bin/sleep", "1"}
	c.Cell.Env = []string{"A=1", "B=2"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Export(&c); err != nil {
			b.Fatal(err)
		}
	}
}
