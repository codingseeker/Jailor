package gate

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	rtmNewLink  = 16
	rtmDelLink  = 17
	rtmNewAddr  = 20
	rtmDelAddr  = 21
	rtmNewRoute = 24
	rtmDelRoute = 25
	rtmGetLink  = 18
	rtmGetAddr  = 22
	nlmsgError  = 2
	nlmsgDone   = 3
)

const (
	nlFRequest = 1
	nlFAck     = 4
	nlFCreate  = 0x400
	nlFExcl    = 0x200

	nlFDump = 0x300
)

const (
	iffUp = 1
)

const (
	rtScopeUniverse = 0
	rtScopeLink     = 253
)

const (
	iflaIfname   = 3
	iflaMaster   = 5
	iflaNetNsFd  = 28
	iflaLinkInfo = 18
)

const (
	iflaInfoKind = 1
	iflaInfoData = 2
)

const (
	vethInfoPeer = 1
)

const (
	rtaOif     = 4
	rtaGateway = 5
)

const (
	ifaLocal = 1
)

const afInet = 2

const (
	kindBridge = "bridge"
	kindVeth   = "veth"
)

const classNetDir = "/sys/class/net"

func NLMSG_ALIGN(n int) int { return (n + 3) &^ 3 }

func attrAlign(n int) int { return (n + 3) &^ 3 }

type nlConn struct {
	fd  int
	seq uint32
}

func newNLConn() (*nlConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("gate: open netlink socket: %w", err)
	}
	local := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, local); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("gate: bind netlink socket: %w", err)
	}
	return &nlConn{fd: fd}, nil
}

func (c *nlConn) Close() {
	if c.fd != 0 {
		_ = syscall.Close(c.fd)
		c.fd = 0
	}
}

type nlMsg struct {
	typ     uint16
	flags   uint16
	payload []byte
}

func (m *nlMsg) addAttr(typ uint16, value []byte) {
	alen := 4 + len(value)
	pad := attrAlign(alen) - alen
	m.payload = append(m.payload,
		byte(alen), byte(alen>>8), byte(typ), byte(typ>>8))
	m.payload = append(m.payload, value...)
	m.payload = append(m.payload, make([]byte, pad)...)
}

func (m *nlMsg) addAttrStr(typ uint16, s string) {
	m.addAttr(typ, append([]byte(s), 0))
}

func (m *nlMsg) addAttrU32(typ uint16, v uint32) {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	m.addAttr(typ, b)
}

func (c *nlConn) send(msg nlMsg) error {
	c.seq++
	seq := c.seq

	hlen := int(unsafe.Sizeof(syscall.NlMsghdr{}))
	buf := make([]byte, hlen+len(msg.payload))
	h := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[0]))
	h.Len = uint32(hlen + len(msg.payload))
	h.Type = msg.typ
	h.Flags = msg.flags
	h.Seq = seq
	copy(buf[hlen:], msg.payload)

	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(c.fd, buf, 0, addr); err != nil {
		return fmt.Errorf("gate: netlink send: %w", err)
	}
	return c.recvAck(seq)
}

func (c *nlConn) recvAck(seq uint32) error {
	buf := make([]byte, 8192)
	hlen := int(unsafe.Sizeof(syscall.NlMsghdr{}))
	for {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return fmt.Errorf("gate: netlink recv: %w", err)
		}
		for off := 0; off+hlen <= n; {
			h := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[off]))
			msgLen := int(h.Len)
			if msgLen < hlen || off+msgLen > n {
				break
			}
			if h.Seq == seq {
				switch h.Type {
				case 0:
				case nlmsgDone:
					return nil
				}
				if h.Type == nlmsgError && msgLen >= hlen+4 {
					errCode := int32(binary.NativeEndian.Uint32(buf[off+hlen:]))
					if errCode == 0 {
						return nil
					}
					return fmt.Errorf("gate: netlink error %d (errno %d)", errCode, errCode)
				}
			}
			off += NLMSG_ALIGN(msgLen)
		}
	}
}

func linkByName(name string) (int, error) {
	data, err := os.ReadFile(classNetDir + "/" + name + "/ifindex")
	if err != nil {
		return 0, fmt.Errorf("gate: interface %q not found: %w", name, err)
	}
	idx, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("gate: parse ifindex for %q: %w", name, err)
	}
	return idx, nil
}

func linkExists(name string) bool {
	_, err := os.Stat(classNetDir + "/" + name)
	return err == nil
}

func isBridge(name string) bool {
	_, err := os.Stat(classNetDir + "/" + name + "/bridge")
	return err == nil
}

func linkUp(name string) error {
	return ifaceFlags(name, true)
}

func ifaceFlags(name string, up bool) error {
	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("gate: open socket: %w", err)
	}
	defer syscall.Close(s)
	var req struct {
		name  [syscall.IFNAMSIZ]byte
		flags int16
	}
	copy(req.name[:], name)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("gate: get flags %s: %v", name, errno)
	}
	if up {
		req.flags |= iffUp
	} else {
		req.flags &^= iffUp
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("gate: set flags %s: %v", name, errno)
	}
	return nil
}

func asIPv4Bytes(ip net.IP) []byte {
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	return v4
}

func parseCIDR(cidr string) (net.IP, int, error) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, 0, fmt.Errorf("gate: parse cidr %q: %w", cidr, err)
	}
	ones, _ := n.Mask.Size()
	return ip, ones, nil
}

func prefixIP(cidr string) (net.IP, int, error) {
	ip, ones, err := parseCIDR(cidr)
	if err != nil {
		return nil, 0, err
	}
	return ip, ones, nil
}

func ensureFileCheck(err error) bool {
	return err != nil && !errors.Is(err, fs.ErrNotExist)
}
