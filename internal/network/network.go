package network

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const DefaultName = "bridge"

const DefaultSubnet = "10.66.0.0/24"

const DefaultBridge = "jailor0"

const stateRoot = "networks"

var ErrExists = errors.New("network: name already exists")

type Network struct {
	Name string `json:"name"`

	ID string `json:"id"`

	Subnet string `json:"subnet"`

	Gateway string `json:"gateway"`

	IPv6 string `json:"ipv6,omitempty"`

	DNS []string `json:"dns,omitempty"`

	Bridge string `json:"bridge"`

	CreatedAt time.Time `json:"createdAt"`
}

type Manager struct {
	Root string
	mu   sync.Mutex
}

func Open(root string) (*Manager, error) {
	if root == "" {
		return nil, errors.New("network: no state root given")
	}
	if err := os.MkdirAll(filepath.Join(root, stateRoot), 0o700); err != nil {
		return nil, fmt.Errorf("network: create state root: %w", err)
	}
	return &Manager{Root: root}, nil
}

func ValidName(s string) bool {
	if s == "" {
		return false
	}
	if s == "none" {
		return false
	}
	if len(s) > 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '_', c == '-', c == '.':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func (m *Manager) Create(name, subnet, gateway, ipv6 string, dns []string) (*Network, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !ValidName(name) {
		return nil, fmt.Errorf("network: invalid name %q (lowercase letters, digits, . _ -, up to 40 chars)", name)
	}
	if _, err := m.load(name); err == nil {
		return nil, ErrExists
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	if subnet == "" {
		subnet = DefaultSubnet
	}
	ipn, err := parseV4Subnet(subnet)
	if err != nil {
		return nil, fmt.Errorf("network: %w", err)
	}
	hostBits, _ := ipn.Mask.Size()
	hostBits = 32 - hostBits
	if hostBits < 2 {
		return nil, fmt.Errorf("network: subnet %q leaves no usable host addresses", subnet)
	}
	if hostBits > 16 {
		return nil, fmt.Errorf("network: subnet %q is too large (need a host part of 16 bits or fewer)", subnet)
	}

	base := v4Uint(ipn.IP.Mask(ipn.Mask))
	if gateway == "" {
		gateway = v4String(base + 1)
	}
	gw, err := parseV4Host(subnet, gateway)
	if err != nil {
		return nil, fmt.Errorf("network: gateway: %w", err)
	}
	if gw == 0 || gw == broadcast(ipn) {
		return nil, fmt.Errorf("network: gateway %s is the network or broadcast address of %s", gateway, subnet)
	}

	bridge := DefaultBridge
	if name != DefaultName {
		bridge = deriveBridge(name)
	}
	for _, other := range m.listLocked() {
		if other.Name != name && other.Bridge == bridge {
			return nil, fmt.Errorf("network: bridge device %q already used by network %q", bridge, other.Name)
		}
	}

	n := &Network{
		Name:      name,
		ID:        newID(),
		Subnet:    subnet,
		Gateway:   net.IP(v4Bytes(gw)).String(),
		IPv6:      ipv6,
		DNS:       append([]string(nil), dns...),
		Bridge:    bridge,
		CreatedAt: time.Now().UTC(),
	}
	if err := normalizeDNS(n); err != nil {
		return nil, err
	}
	if err := validateIPv6(n.IPv6); err != nil {
		return nil, err
	}
	if err := m.save(n); err != nil {
		return nil, err
	}
	if err := m.saveAllocsLocked(n.Name, map[string]bool{}); err != nil {
		return nil, err
	}
	return n, nil
}

func (m *Manager) Get(name string) (*Network, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.load(name)
}

func (m *Manager) Default() (*Network, error) {
	if n, err := m.Get(DefaultName); err == nil {
		return n, nil
	}
	return m.Create(DefaultName, "", "", "", nil)
}

func (m *Manager) List() ([]Network, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listLocked(), nil
}

func (m *Manager) Remove(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if name == DefaultName {
		return errors.New("network: the default network cannot be removed")
	}
	allocs, err := m.loadAllocsLocked(name)
	if err != nil {
		return err
	}
	if len(allocs) > 0 {
		return fmt.Errorf("network: %s still has %d allocated address(es)", name, len(allocs))
	}
	return os.RemoveAll(m.dir(name))
}

func (m *Manager) Networks() []Network {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.listLocked()
}

func (m *Manager) Allocate(name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, err := m.load(name)
	if err != nil {
		return "", err
	}
	ipn, err := parseV4Subnet(n.Subnet)
	if err != nil {
		return "", err
	}
	base := v4Uint(ipn.IP.Mask(ipn.Mask))
	hostBits, _ := ipn.Mask.Size()
	hostBits = 32 - hostBits
	gw := v4Uint(net.ParseIP(n.Gateway).To4())
	bcast := broadcast(ipn)

	unlock, err := m.flock(name)
	if err != nil {
		return "", err
	}
	defer unlock()
	allocs, err := m.loadAllocsLocked(name)
	if err != nil {
		return "", err
	}
	for i := uint32(1); i < (1 << hostBits); i++ {
		ip := base + i
		if ip == bcast || ip == gw {
			continue
		}
		s := v4String(ip)
		if allocs[s] {
			continue
		}
		allocs[s] = true
		if err := m.saveAllocsLocked(name, allocs); err != nil {
			return "", err
		}
		return s, nil
	}
	return "", fmt.Errorf("network: %s (%s) is exhausted", name, n.Subnet)
}

func (m *Manager) Release(name, address string) error {
	if address == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.load(name); err != nil {
		return err
	}
	unlock, err := m.flock(name)
	if err != nil {
		return err
	}
	defer unlock()
	allocs, err := m.loadAllocsLocked(name)
	if err != nil {
		return err
	}
	if !allocs[address] {

		return nil
	}
	delete(allocs, address)
	return m.saveAllocsLocked(name, allocs)
}

func (m *Manager) Allocations(name string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.load(name); err != nil {
		return nil, err
	}
	allocs, err := m.loadAllocsLocked(name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(allocs))
	for a := range allocs {
		out = append(out, a)
	}
	sort.Strings(out)
	return out, nil
}

func (n *Network) CIDR(address string) string {
	return address + fmt.Sprintf("/%d", n.prefixLen())
}

func (n *Network) GatewayCIDR() string {
	return n.Gateway + fmt.Sprintf("/%d", n.prefixLen())
}

func (n *Network) prefixLen() int {
	if _, ipn, err := net.ParseCIDR(n.Subnet); err == nil {
		if o, _ := ipn.Mask.Size(); o > 0 {
			return o
		}
	}
	return 24
}

func newID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("net-%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b[:])
}

func (m *Manager) dir(name string) string     { return filepath.Join(m.Root, stateRoot, name) }
func (m *Manager) netFile(name string) string { return filepath.Join(m.dir(name), "network.json") }
func (m *Manager) allocFile(name string) string {
	return filepath.Join(m.dir(name), "allocations.json")
}

func (m *Manager) load(name string) (*Network, error) {
	data, err := os.ReadFile(m.netFile(name))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("network: no such network %q (create it with `jailor network create`): %w", name, os.ErrNotExist)
		}
		return nil, err
	}
	var n Network
	if err := json.Unmarshal(data, &n); err != nil {
		return nil, fmt.Errorf("network: decode %s: %w", name, err)
	}
	return &n, nil
}

func (m *Manager) save(n *Network) error {
	if n == nil || n.Name == "" {
		return errors.New("network: cannot save a nameless network")
	}
	if err := os.MkdirAll(m.dir(n.Name), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.netFile(n.Name) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.netFile(n.Name))
}

func (m *Manager) listLocked() []Network {
	dir := filepath.Join(m.Root, stateRoot)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []Network
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		data, err := os.ReadFile(m.netFile(e.Name()))
		if err != nil {
			continue
		}
		var n Network
		if json.Unmarshal(data, &n) == nil && n.Name != "" {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (m *Manager) loadAllocsLocked(name string) (map[string]bool, error) {
	data, err := os.ReadFile(m.allocFile(name))
	if os.IsNotExist(err) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Allocations []string `json:"allocations"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("network: decode allocations for %s: %w", name, err)
	}
	out := make(map[string]bool, len(doc.Allocations))
	for _, a := range doc.Allocations {
		out[a] = true
	}
	return out, nil
}

func (m *Manager) saveAllocsLocked(name string, allocs map[string]bool) error {
	keys := make([]string, 0, len(allocs))
	for a := range allocs {
		keys = append(keys, a)
	}
	sort.Strings(keys)
	doc := struct {
		Allocations []string `json:"allocations"`
	}{Allocations: keys}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.allocFile(name) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.allocFile(name))
}

func (m *Manager) flock(name string) (func(), error) {
	path := filepath.Join(m.dir(name), ".lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

func parseV4Subnet(cidr string) (*net.IPNet, error) {
	ip, ipn, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %q: %w", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("subnet %q is not IPv4", cidr)
	}
	return ipn, nil
}

func parseV4Host(subnet, host string) (uint32, error) {
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return 0, fmt.Errorf("invalid IPv4 address %q", host)
	}
	_, ipn, err := net.ParseCIDR(subnet)
	if err != nil {
		return 0, err
	}
	if !ipn.Contains(ip) {
		return 0, fmt.Errorf("%s is not within %s", host, subnet)
	}
	return v4Uint(ip.To4()), nil
}

func v4Uint(ip net.IP) uint32 {
	b := ip.To4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func v4Bytes(u uint32) []byte {
	return []byte{byte(u >> 24), byte(u >> 16), byte(u >> 8), byte(u)}
}

func v4String(u uint32) string {
	return net.IP(v4Bytes(u)).String()
}

func broadcast(ipn *net.IPNet) uint32 {
	bits, _ := ipn.Mask.Size()
	hostBits := 32 - bits
	base := v4Uint(ipn.IP.Mask(ipn.Mask))
	if hostBits >= 32 {
		return ^uint32(0)
	}
	return base | uint32((uint64(1)<<hostBits)-1)
}

func deriveBridge(name string) string {
	s := "jailor-" + name
	if len(s) > 15 {
		s = s[:15]
	}
	return s
}

func normalizeDNS(n *Network) error {
	out := make([]string, 0, len(n.DNS))
	for _, d := range n.DNS {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		if net.ParseIP(d) == nil {
			return fmt.Errorf("network: invalid DNS server %q", d)
		}
		out = append(out, d)
	}
	n.DNS = out
	return nil
}

func validateIPv6(cidr string) error {
	if cidr == "" {
		return nil
	}
	ip, ipn, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() != nil {
		return fmt.Errorf("network: invalid IPv6 subnet %q", cidr)
	}
	if ones, _ := ipn.Mask.Size(); ones < 64 {
		return fmt.Errorf("network: IPv6 subnet %q is too large (prefix >= 64 required)", cidr)
	}
	return nil
}
