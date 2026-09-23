package gate

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
)

type Mode string

const (
	ModeNone   Mode = "none"
	ModeBridge Mode = "bridge"
)

type Gate struct {
	Mode     Mode
	Name     string
	Bridge   string
	Subnet   string
	VethHost string
	IP       string
	Gateway  string
	Managed  bool
	Ports    []Port
}

type Port struct {
	Host  int
	Guest int
}

const DefaultBridge = "jailor0"
const DefaultSubnet = "10.66.0.0/24"
const defaultGatewayOffset = 1
const GuestVethName = "eth0"

func ParseMode(s string) (Mode, error) {
	switch s {
	case "", "none":
		return ModeNone, nil
	case "bridge":
		return ModeBridge, nil
	default:
		return "", fmt.Errorf("gate: unknown network mode %q (want none or bridge)", s)
	}
}

func New(mode string) (*Gate, error) {
	m, err := ParseMode(mode)
	if err != nil {
		return nil, err
	}
	if m == ModeBridge {
		return &Gate{Mode: m, Bridge: DefaultBridge, Subnet: DefaultSubnet}, nil
	}
	return &Gate{Mode: m}, nil
}

func (g *Gate) RequiresSetup() bool {
	return g != nil && g.Mode == ModeBridge
}

func (g *Gate) Assign(ipCidr, gwCidr string) error {
	if g == nil {
		return errors.New("gate: no gate to assign to")
	}
	g.IP = ipCidr
	g.Gateway = gwCidr
	g.Managed = true
	return g.Validate()
}

func (g *Gate) Validate() error {
	if g == nil {
		return errors.New("gate: no gate configured")
	}
	if g.Mode != ModeNone && g.Mode != ModeBridge {
		return fmt.Errorf("gate: invalid mode %q", g.Mode)
	}
	if g.Mode == ModeBridge {
		if _, _, err := net.ParseCIDR(g.Subnet); err != nil {
			return fmt.Errorf("gate: invalid subnet %q: %w", g.Subnet, err)
		}
		if g.IP != "" {
			ip, _, err := net.ParseCIDR(g.IP)
			if err != nil {
				return fmt.Errorf("gate: invalid jail address %q: %w", g.IP, err)
			}
			if g.Gateway != "" {
				gw, _, gerr := net.ParseCIDR(g.Gateway)
				if gerr != nil {
					return fmt.Errorf("gate: invalid gateway %q: %w", g.Gateway, gerr)
				}
				if ip.Equal(gw) {
					return fmt.Errorf("gate: jail address %s cannot equal the gateway", ip)
				}
			}
		}
	}
	for _, p := range g.Ports {
		if p.Host < 1 || p.Host > 65535 || p.Guest < 1 || p.Guest > 65535 {
			return fmt.Errorf("gate: invalid port mapping %d:%d", p.Host, p.Guest)
		}
	}
	return nil
}

var allocMu sync.Mutex
var usedAddrs = map[string]bool{}

func (g *Gate) Allocate() (ip, gateway string, err error) {
	allocMu.Lock()
	defer allocMu.Unlock()

	base := g.BaseIP()
	prefix := netPrefix(g.Subnet)
	if base == nil {
		return "", "", fmt.Errorf("gate: invalid subnet %q", g.Subnet)
	}
	gatewayIP := hostIP(base, defaultGatewayOffset)

	for off := 2; off < 255; off++ {
		candidate := hostIP(base, byte(off))
		addr := candidate.String() + fmt.Sprintf("/%d", prefix)
		if usedAddrs[addr] {
			continue
		}
		if byte(off) == 255 {
			continue
		}
		usedAddrs[addr] = true
		return addr, gatewayIP.String() + fmt.Sprintf("/%d", prefix), nil
	}
	return "", "", fmt.Errorf("gate: subnet %s exhausted", g.Subnet)
}

func Release(addr string) {
	allocMu.Lock()
	delete(usedAddrs, addr)
	allocMu.Unlock()
}

func (g *Gate) BaseIP() net.IP {
	ip, n, err := net.ParseCIDR(g.Subnet)
	if err != nil {
		return nil
	}
	return ip.Mask(n.Mask)
}

func hostIP(base net.IP, off byte) net.IP {
	out := make(net.IP, 4)
	copy(out, base.To4())
	out[3] += off
	return out
}

func netPrefix(cidr string) int {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return 24
	}
	ones, _ := n.Mask.Size()
	return ones
}

func sortedHosts(cidr string) []string {
	base := net.ParseIP(cidr)
	if base == nil {
		return nil
	}
	var out []string
	for i := 0; i < 254; i++ {
		out = append(out, hostIP(base, byte(1+i)).String())
	}
	sort.Strings(out)
	return out
}
