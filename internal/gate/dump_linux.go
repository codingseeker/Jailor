package gate

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

func defaultRouteLink() (int, error) {
	c, err := newNLConn()
	if err != nil {
		return 0, err
	}
	defer c.Close()

	c.seq++
	hlen := int(unsafe.Sizeof(syscall.NlMsghdr{}))
	rtlen := int(unsafe.Sizeof(syscall.RtMsg{}))
	buf := make([]byte, hlen+rtlen)
	h := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[0]))
	h.Len = uint32(hlen + rtlen)
	h.Type = rtmNewRoute
	h.Flags = uint16(nlFRequest | nlFDump)
	h.Seq = c.seq

	addr := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(c.fd, buf, 0, addr); err != nil {
		return 0, fmt.Errorf("gate: route dump send: %w", err)
	}

	seen := make([]byte, 16384)
	for {
		n, _, err := syscall.Recvfrom(c.fd, seen, 0)
		if err != nil {
			return 0, fmt.Errorf("gate: route dump recv: %w", err)
		}
		for off := 0; off+hlen <= n; {
			msg := (*syscall.NlMsghdr)(unsafe.Pointer(&seen[off]))
			ml := int(msg.Len)
			if ml < hlen || off+ml > n {
				break
			}
			if msg.Seq != c.seq {
				off += NLMSG_ALIGN(ml)
				continue
			}
			if msg.Type == 0 || msg.Type == nlmsgDone {
				return 0, nil
			}
			if msg.Type == nlmsgError && ml >= hlen+4 {
				ec := int32(binary.NativeEndian.Uint32(seen[off+hlen:]))
				if ec != 0 {
					return 0, fmt.Errorf("gate: route dump error %d", ec)
				}
			}
			if int16(msg.Type) == int16(rtmNewRoute) && ml >= hlen+rtlen {
				r := (*syscall.RtMsg)(unsafe.Pointer(&seen[off+hlen]))
				if r.Dst_len == 0 && r.Table == 254 && r.Family == afInet {
					attrs := parseAttrs(seen[off+hlen+rtlen : off+ml])
					if oif, ok := attrs[rtaOif]; ok && len(oif) >= 4 {
						return int(binary.NativeEndian.Uint32(oif)), nil
					}
				}
			}
			off += NLMSG_ALIGN(ml)
		}
	}
}
func parseAttrs(b []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	for len(b) >= 4 {
		alen := int(uint16(b[0]) | uint16(b[1])<<8)
		atyp := uint16(b[2]) | uint16(b[3])<<8
		if alen < 4 || alen > len(b) {
			break
		}
		if _, ok := out[atyp]; !ok {
			out[atyp] = b[4:alen]
		}
		b = b[attrAlign(alen):]
	}
	return out
}
func ifnameForIndex(idx int) string {
	return ifnameForIndexStr(strconv.Itoa(idx))
}

func ifnameForIndexStr(idxStr string) string {
	idx, err := strconv.Atoi(strings.TrimSpace(idxStr))
	if err != nil || idx <= 0 {
		return ""
	}
	entries, err := os.ReadDir(classNetDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		data, err := os.ReadFile(classNetDir + "/" + e.Name() + "/ifindex")
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(data)) == idxStr {
			return e.Name()
		}
	}
	return ""
}
