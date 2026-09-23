package warden

import (
	"testing"

	"jailor/internal/bars"
	"jailor/internal/config"
)

var benchOpts = Options{
	Args:   []string{"/bin/echo", "bench"},
	Bars:   []bars.Kind{bars.PID, bars.UTS, bars.Mount},
	Config: &config.Config{},
}

func BenchmarkPrepareCell(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := New(benchOpts)
		init, _, err := w.prepareCell("bench")
		if err != nil {
			b.Fatal(err)
		}
		_ = init
	}
}

func BenchmarkBuildInit(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := New(benchOpts)
		_ = w.buildInit()
		_ = w.bars()
	}
}

func BenchmarkNewRecord(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := New(benchOpts)
		_ = w.newRecord(w.buildInit(), "bench")
	}
}
