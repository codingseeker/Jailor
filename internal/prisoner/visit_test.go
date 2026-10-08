//go:build linux

package prisoner

import (
	"fmt"
	"os"
	"testing"
	"time"

	"jailor/internal/jail"
)

var self string

func visitorProbe(kind string) int {
	switch kind {
	case "hostname":
		h, err := os.Hostname()
		if err != nil {
			fmt.Printf("hostname=err:%v\n", err)
			return 1
		}
		fmt.Printf("hostname=%s\n", h)
	case "selfns":
		names := []string{"mnt", "uts", "ipc", "pid", "net", "user", "cgroup"}
		for _, n := range names {
			if link, err := os.Readlink("/proc/self/ns/" + n); err == nil {
				fmt.Printf("ns_%s=%s\n", n, link)
			}
		}
	case "sleep":
		fmt.Printf("jail-sleep\n")
		time.Sleep(30 * time.Second)
	}
	return 0
}

func TestMain(m *testing.M) {
	switch {
	case len(os.Args) > 1 && os.Args[1] == jail.InitArg:
		os.Exit(jail.RunInit())
	case len(os.Args) > 1 && os.Args[1] == jail.StagerArg:
		os.Exit(jail.RunStager())
	case len(os.Args) > 1 && os.Args[1] == "__nsenter":
		os.Exit(jail.RunNSEnter())
	case len(os.Args) > 1 && os.Args[1] == "__visitor":
		os.Exit(jail.RunVisitor())
	case len(os.Args) > 1 && os.Args[1] == "__probe":
		if len(os.Args) > 2 {
			os.Exit(visitorProbe(os.Args[2]))
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func init() {
	self, _ = os.Executable()
}
