#!/usr/bin/env bash
set -euo pipefail

ROOTFS="${1:-rootfs}"

mkdir -p "$ROOTFS"/{bin,sbin,usr/bin,usr/sbin,lib64,tmp,proc,dev,etc}

BINS=(/bin/sh /usr/bin/cat /usr/bin/echo /usr/bin/ls /usr/bin/mkdir /usr/bin/stat /usr/bin/uname /usr/bin/grep /usr/bin/mount /usr/bin/ps /usr/bin/hostname /usr/bin/touch /usr/bin/pwd)

copy_bin() {
	local src="$1"
	if [ ! -e "$src" ]; then
		return
	fi
	local real
	real="$(readlink -f "$src")"
	local dest="$ROOTFS/bin/$(basename "$real")"
	cp -a "$real" "$dest"
	local line lib path
	while IFS= read -r line; do
		line="$(echo "$line" | xargs)"
		[ -z "$line" ] && continue
		lib="${line%% *}"
		[ "$lib" = "linux-vdso.so.1" ] && continue
		[ "${lib:0:1}" = "/" ] && lib="$(basename "$lib")"
		path="$(echo "$line" | grep -oP '(?<==> ).*?(?= \()' || true)"
		[ -z "$path" ] && continue
		local libreal
		libreal="$(readlink -f "$path")"
		cp -n -a "$libreal" "$ROOTFS/lib64/" 2>/dev/null || true
		local realname
		realname="$(basename "$libreal")"
		if [ "$lib" != "$realname" ]; then
			ln -sfn "$realname" "$ROOTFS/lib64/$lib" 2>/dev/null || true
		fi
	done < <(ldd "$real")
}

for b in "${BINS[@]}"; do
	copy_bin "$b"
done

if [ -e /lib64/ld-linux-x86-64.so.2 ]; then
	ldreal="$(readlink -f /lib64/ld-linux-x86-64.so.2)"
	cp -a "$ldreal" "$ROOTFS/lib64/" 2>/dev/null || true
	if [ "$(basename "$ldreal")" != "ld-linux-x86-64.so.2" ]; then
		ln -sfn "$(basename "$ldreal")" "$ROOTFS/lib64/ld-linux-x86-64.so.2" 2>/dev/null || true
	fi
fi

for d in bin sbin usr/bin usr/sbin; do
	ln -sfn bash "$ROOTFS/bin/sh" 2>/dev/null || true
done
ln -sfn ../bin/sh "$ROOTFS/sbin/sh" 2>/dev/null || true
ln -sfn ../../bin/sh "$ROOTFS/usr/bin/sh" 2>/dev/null || true
ln -sfn ../../bin/sh "$ROOTFS/usr/sbin/sh" 2>/dev/null || true

ln -sfn /proc/self/fd "$ROOTFS/dev/fd" 2>/dev/null || true

echo "rootfs ready: $ROOTFS"
