package gate

import (
	"fmt"
	"syscall"
	"unsafe"
)

func createBridge(name string) error {
	if linkExists(name) {
		return nil
	}
	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var ifm syscall.IfInfomsg
	ifm.Family = afInet

	msg := nlMsg{typ: rtmNewLink, flags: nlFRequest | nlFAck | nlFCreate}
	msg.payload = ifmPayload(ifm)
	msg.addAttrStr(iflaIfname, name)
	li := &nlMsg{}
	li.addAttrStr(iflaInfoKind, kindBridge)
	msg.addAttr(uint16(iflaLinkInfo), li.payload)

	if err := c.send(msg); err != nil {
		return fmt.Errorf("gate: create bridge %s: %w", name, err)
	}
	return linkUp(name)
}

func createVethPair(nameA, nameB string) error {
	if linkExists(nameA) {
		return nil
	}
	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var ifm syscall.IfInfomsg
	ifm.Family = afInet
	flags := uint16(nlFRequest | nlFAck | nlFCreate)

	msg := nlMsg{typ: rtmNewLink, flags: flags}
	msg.payload = ifmPayload(ifm)
	msg.addAttrStr(iflaIfname, nameA)
	peer := nlMsg{}
	var pfm syscall.IfInfomsg
	pfm.Family = afInet
	peer.payload = ifmPayload(pfm)
	peer.addAttrStr(iflaIfname, nameB)

	li := nlMsg{}
	li.addAttrStr(iflaInfoKind, kindVeth)
	li.addAttr(uint16(iflaInfoData), peer.payload)

	msg.addAttr(uint16(iflaLinkInfo), li.payload)

	if err := c.send(msg); err != nil {
		return fmt.Errorf("gate: create veth pair %s/%s: %w", nameA, nameB, err)
	}
	return nil
}
func ifmPayload(ifm syscall.IfInfomsg) []byte {
	b := make([]byte, int(unsafe.Sizeof(ifm)))
	*(*syscall.IfInfomsg)(unsafe.Pointer(&b[0])) = ifm
	return b
}

func setLinkMaster(iface, bridge string) error {
	idx, err := linkByName(iface)
	if err != nil {
		return err
	}
	master, err := linkByName(bridge)
	if err != nil {
		return err
	}
	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var ifm syscall.IfInfomsg
	ifm.Family = afInet
	ifm.Index = int32(idx)

	msg := nlMsg{typ: rtmNewLink, flags: nlFRequest | nlFAck}
	msg.payload = ifmPayload(ifm)
	msg.addAttrU32(iflaMaster, uint32(master))
	return c.send(msg)
}
func moveLinkInto(name string, pid int) error {
	idx, err := linkByName(name)
	if err != nil {
		return err
	}
	ns, err := netnsFile(pid)
	if err != nil {
		return err
	}
	defer ns.Close()

	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var ifm syscall.IfInfomsg
	ifm.Family = afInet
	ifm.Index = int32(idx)

	msg := nlMsg{typ: rtmNewLink, flags: nlFRequest | nlFAck}
	msg.payload = ifmPayload(ifm)
	msg.addAttrU32(iflaNetNsFd, uint32(ns.Fd()))
	if err := c.send(msg); err != nil {
		return fmt.Errorf("gate: move %s into netns of pid %d: %w", name, pid, err)
	}
	return nil
}

func renameInNetns(oldName, newName string) error {
	idx, err := linkByName(oldName)
	if err != nil {
		return err
	}
	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var ifm syscall.IfInfomsg
	ifm.Family = afInet
	ifm.Index = int32(idx)

	msg := nlMsg{typ: rtmNewLink, flags: nlFRequest | nlFAck}
	msg.payload = ifmPayload(ifm)
	msg.addAttrStr(iflaIfname, newName)
	return c.send(msg)
}

func deleteLink(name string) error {
	idx, err := linkByName(name)
	if err != nil {
		return err
	}
	c, err := newNLConn()
	if err != nil {
		return err
	}
	defer c.Close()

	var ifm syscall.IfInfomsg
	ifm.Family = afInet
	ifm.Index = int32(idx)

	msg := nlMsg{typ: rtmDelLink, flags: nlFRequest | nlFAck}
	msg.payload = ifmPayload(ifm)
	if err := c.send(msg); err != nil {
		return fmt.Errorf("gate: delete link %s: %w", name, err)
	}
	return nil
}
