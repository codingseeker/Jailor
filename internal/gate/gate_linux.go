package gate

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func (g *Gate) bridgeAddr() string {
	base := g.BaseIP()
	if base == nil {
		return ""
	}
	return hostIP(base, defaultGatewayOffset).String() + fmt.Sprintf("/%d", netPrefix(g.Subnet))
}
func hostVethName(jailID string) string {
	id := jailID
	if len(id) > 8 {
		id = id[len(id)-8:]
	}
	return "v" + id
}
func (g *Gate) Setup(jailID string, prisonerPID int) error {
	if g == nil {
		return errors.New("gate: no gate to set up")
	}
	if err := g.Validate(); err != nil {
		return err
	}

	if g.Mode == ModeNone {
		return withNetns(prisonerPID, func() error {
			return linkUp("lo")
		})
	}
	if err := createBridge(g.Bridge); err != nil {
		return err
	}
	_ = linkUp(g.Bridge)
	if err := ensureBridgeAddr(g.Bridge, g.bridgeAddr()); err != nil {
		return err
	}

	hostName := hostVethName(jailID)
	guestName := "veth-pair-" + short(idTail(jailID))
	if err := createVethPair(hostName, guestName); err != nil {
		return fmt.Errorf("%w (host veth %s)", err, hostName)
	}
	g.VethHost = hostName
	if err := setLinkMaster(hostName, g.Bridge); err != nil {
		_ = deleteLink(hostName)
		return err
	}
	if err := linkUp(hostName); err != nil {
		_ = deleteLink(hostName)
		return err
	}
	ipCidr := g.IP
	gwCidr := g.Gateway
	if ipCidr == "" || gwCidr == "" {
		var err error
		ipCidr, gwCidr, err = g.Allocate()
		if err != nil {
			_ = deleteLink(hostName)
			return err
		}
	}
	g.IP = ipCidr
	g.Gateway = gwCidr

	gwIP, _, _ := net.ParseCIDR(gwCidr)
	_ = gwIP
	if err := addAddrTo(hostName, gwCidr); err != nil {
		_ = deleteLink(hostName)
		return err
	}

	if err := moveLinkInto(guestName, prisonerPID); err != nil {
		_ = deleteLink(hostName)
		return err
	}

	guestErr := withNetns(prisonerPID, func() error {
		if err := linkUp("lo"); err != nil {
			return err
		}
		if err := renameInNetns(guestName, GuestVethName); err != nil {
			return err
		}
		if err := addAddrTo(GuestVethName, g.IP); err != nil {
			return err
		}
		return addDefaultRoute(GuestVethName, gatewayOf(gwCidr))
	})
	if guestErr != nil {
		_ = deleteLink(hostName)
		return fmt.Errorf("gate: configure jail network: %w", guestErr)
	}

	g.routeAndNAT(jailID)
	g.publishIPTableRules(jailID)
	return nil
}

func short(s string) string {
	if len(s) <= 4 {
		return s
	}
	return s[len(s)-4:]
}

func idTail(s string) string { return s }

func gatewayOf(cidr string) net.IP {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	return ip
}

func ensureBridgeAddr(bridge, cidr string) error {
	if err := addAddrTo(bridge, cidr); err != nil {
		return nil
	}
	return nil
}
func (g *Gate) routeAndNAT(_ string) {
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)

	subnet := g.Subnet
	outIface := defaultEgressIface()
	if outIface == "" || outIface == g.Bridge {
		return
	}
	runIPTables("-t", "nat", "-C", "POSTROUTING", "-s", subnet, "!", "-o", g.Bridge, "-j", "MASQUERADE")
	_ = runIPTables("-t", "nat", "-A", "POSTROUTING", "-s", subnet, "!", "-o", g.Bridge, "-j", "MASQUERADE")
	_ = runIPTables("-A", "FORWARD", "-i", g.Bridge, "-o", outIface, "-j", "ACCEPT")
	_ = runIPTables("-A", "FORWARD", "-i", outIface, "-o", g.Bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
}

func defaultEgressIface() string {
	link, err := defaultRouteLink()
	if err != nil || link == 0 {
		return ""
	}
	name := ifnameForIndex(link)
	if name == "" {
		return ""
	}
	if name == DefaultBridge {
		return ""
	}
	return name
}

func runIPTables(args ...string) error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return err
	}
	cmd := exec.Command("iptables", args...)
	return cmd.Run()
}
func (g *Gate) publishIPTableRules(_ string) {
	if g == nil || g.Mode != ModeBridge || len(g.Ports) == 0 {
		return
	}
	guestIP, _, err := net.ParseCIDR(g.IP)
	if err != nil {
		return
	}
	for _, p := range g.Ports {
		_ = runIPTables("-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", fmt.Sprint(p.Host),
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", guestIP, p.Guest))
		_ = runIPTables("-A", "FORWARD", "-p", "tcp", "-d", guestIP.String(), "--dport", fmt.Sprint(p.Guest), "-j", "ACCEPT")
	}
}
func (g *Gate) unpublishIPTableRules() {
	if g == nil || g.Mode != ModeBridge || len(g.Ports) == 0 {
		return
	}
	guestIP, _, err := net.ParseCIDR(g.IP)
	if err != nil {
		return
	}
	for _, p := range g.Ports {
		_ = runIPTables("-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", fmt.Sprint(p.Host),
			"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", guestIP, p.Guest))
		_ = runIPTables("-D", "FORWARD", "-p", "tcp", "-d", guestIP.String(), "--dport", fmt.Sprint(p.Guest), "-j", "ACCEPT")
	}
}
func (g *Gate) Teardown(jailID string) {
	if g == nil {
		return
	}
	if g.Mode != ModeBridge {
		if !g.Managed && g.IP != "" {
			Release(g.IP)
		}
		return
	}
	g.cleanupIPTables()
	g.unpublishIPTableRules()
	host := g.VethHost
	if host == "" {
		host = hostVethName(jailID)
	}
	if linkExists(host) {
		_ = deleteLink(host)
	}
	if g.IP != "" && !g.Managed {
		Release(g.IP)
	}
	g.maybeRemoveBridge()
}
func (g *Gate) cleanupIPTables() {
	if g == nil || g.Mode != ModeBridge {
		return
	}
	subnet := g.Subnet
	_ = runIPTables("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", g.Bridge, "-j", "MASQUERADE")
	outIface := defaultEgressIface()
	if outIface != "" && outIface != g.Bridge {
		_ = runIPTables("-D", "FORWARD", "-i", g.Bridge, "-o", outIface, "-j", "ACCEPT")
		_ = runIPTables("-D", "FORWARD", "-i", outIface, "-o", g.Bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}
}
func (g *Gate) maybeRemoveBridge() {
	if g == nil || g.Mode != ModeBridge {
		return
	}
	if !linkExists(g.Bridge) {
		return
	}
	entries, err := os.ReadDir(classNetDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if name == g.Bridge {
			continue
		}
		if isBridgeMemberOn(name, g.Bridge) {
			return
		}
	}
	_ = deleteLink(g.Bridge)
}
func Sweep(runningIDs map[string]bool) int {
	return SweepBridge(DefaultBridge, runningIDs)
}
func SweepBridge(bridge string, runningIDs map[string]bool) int {
	if bridge == "" {
		bridge = DefaultBridge
	}
	host, err := os.ReadDir(classNetDir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range host {
		name := e.Name()
		if !strings.HasPrefix(name, "v") || len(name) != 9 {
			continue
		}
		if !linkExists(name) {
			continue
		}
		if !isBridgeMemberOn(name, bridge) {
			continue
		}
		tail := name[1:]
		owned := false
		for id := range runningIDs {
			if hostVethName(id) == name || strings.HasSuffix(hostVethName(id), tail) {
				owned = true
				break
			}
		}
		if owned {
			continue
		}
		if deleteLink(name) == nil {
			removed++
		}
	}
	return removed
}
func TeardownAll() {
	TeardownBridge(DefaultBridge)
}
func TeardownBridge(bridge string) {
	if bridge == "" {
		bridge = DefaultBridge
	}
	entries, err := os.ReadDir(classNetDir)
	if err == nil {
		for _, e := range entries {
			name := e.Name()
			if name == bridge {
				continue
			}
			if isBridgeMemberOn(name, bridge) {
				_ = deleteLink(name)
			}
		}
	}
	for _, subnet := range []string{DefaultSubnet} {
		_ = runIPTables("-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE")
	}
	outIface := defaultEgressIface()
	if outIface != "" && outIface != bridge {
		_ = runIPTables("-D", "FORWARD", "-i", bridge, "-o", outIface, "-j", "ACCEPT")
		_ = runIPTables("-D", "FORWARD", "-i", outIface, "-o", bridge, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}
	if linkExists(bridge) {
		_ = deleteLink(bridge)
	}
}

func isBridgeMember(name string) bool {
	return isBridgeMemberOn(name, DefaultBridge)
}

func isBridgeMemberOn(name, bridge string) bool {
	data, err := os.ReadFile(filepath.Join(classNetDir, name, "master"))
	if err != nil {
		return false
	}
	idx := strings.TrimSpace(string(data))
	masterName := ifnameForIndexStr(idx)
	return masterName == bridge
}
