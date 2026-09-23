package gate

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

func addAddrTo(iface, cidr string) error {
	idx, err := linkByName(iface)
	if err != nil {
		return err
	}
	ip, ones, err := prefixIP(cidr)
	if err != nil {
		return err
	}
	ipb := asIPv4Bytes(ip)
	if ipb == nil {
		return fmt.Errorf("gate: %s is not an IPv4 address", cidr)
	}

	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var ifa syscall.IfAddrmsg
	ifa.Family = afInet
	ifa.Prefixlen = uint8(ones)
	ifa.Index = uint32(idx)
	ifa.Scope = rtScopeLink

	msg := nlMsg{typ: rtmNewAddr, flags: nlFRequest | nlFAck | nlFCreate | nlFExcl}
	msg.payload = ifaPayload(ifa)
	msg.addAttr(ifaLocal, ipb)
	if err := c.send(msg); err != nil {
		return fmt.Errorf("gate: add addr %s to %s: %w", cidr, iface, err)
	}
	return nil
}

func ifaPayload(ifa syscall.IfAddrmsg) []byte {
	b := make([]byte, int(unsafe.Sizeof(ifa)))
	*(*syscall.IfAddrmsg)(unsafe.Pointer(&b[0])) = ifa
	return b
}
func addDefaultRoute(iface string, gateway net.IP) error {
	idx, err := linkByName(iface)
	if err != nil {
		return err
	}
	gw := asIPv4Bytes(gateway)
	if gw == nil {
		return fmt.Errorf("gate: invalid IPv4 gateway %s", gateway)
	}

	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var rm syscall.RtMsg
	rm.Family = afInet
	rm.Dst_len = 0
	rm.Table = 254
	rm.Protocol = 3
	rm.Scope = rtScopeLink
	rm.Type = 1

	msg := nlMsg{typ: rtmNewRoute, flags: nlFRequest | nlFAck | nlFCreate | nlFExcl}
	msg.payload = rtPayload(rm)
	msg.addAttrU32(rtaOif, uint32(idx))
	msg.addAttr(rtaGateway, gw)
	if err := c.send(msg); err != nil {
		return fmt.Errorf("gate: add default route: %w", err)
	}
	return nil
}

func rtPayload(rm syscall.RtMsg) []byte {
	b := make([]byte, int(unsafe.Sizeof(rm)))
	*(*syscall.RtMsg)(unsafe.Pointer(&b[0])) = rm
	return b
}
