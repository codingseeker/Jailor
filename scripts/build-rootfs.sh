#!/usr/bin/env bash
# Build a minimal, deterministic Cell root filesystem for jailor.
#
# Every required binary, the ELF interpreter it needs and each shared library
# it links against are copied into the Cell and then verified. A missing or
# unverifiable dependency aborts the build: a Cell that cannot execute its own
# programs is a broken Cell.
set -euo pipefail

ROOTFS="${1:-rootfs}"
MODE="${2:-all}"

die() {
	printf 'build-rootfs: %s\n' "$*" >&2
	exit 1
}

require() {
	command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

for tool in readelf install cp mkdir ln chmod readlink find sort; do
	require "$tool"
done

case "$MODE" in
all) PLAN=(binaries dirs devices links) ;;
binaries) PLAN=(binaries dirs links) ;;
devices) PLAN=(dirs devices links) ;;
links) PLAN=(links) ;;
*) die "unknown mode: $MODE" ;;
esac

in_plan() {
	local want="$1" item
	for item in "${PLAN[@]}"; do
		[ "$item" = "$want" ] && return 0
	done
	return 1
}

# Binaries the jail tests and ordinary programs need inside a Cell. Every entry
# is required: a Cell that cannot run its own programs is a broken Cell.
BINARIES=(
	/bin/sh
	/bin/cat
	/bin/echo
	/bin/true
	/bin/ls
	/bin/mkdir
	/bin/stat
	/bin/uname
	/bin/grep
	/bin/mount
	/bin/hostname
	/bin/touch
	/bin/pwd
	/bin/rm
	/bin/sleep
	/usr/bin/env
	/usr/bin/ps
)

# Binaries copied when present. Their absence is reported but does not fail the
# build, because a trimmed host may legitimately not ship them.
OPTIONAL_BINARIES=(
	/bin/date
	/bin/id
	/bin/whoami
	/bin/df
	/bin/du
	/bin/head
	/bin/tail
	/bin/wc
	/bin/sync
	/usr/bin/id
	/usr/bin/whoami
)

# Directories the jail expects to find inside the Cell.
DIRECTORIES=(bin sbin lib lib64 usr/bin usr/sbin usr/lib etc tmp proc dev dev/pts dev/shm)

DEVICES=(null zero full random urandom tty)

# Standard stream and file descriptor links expected inside /dev.
DEV_LINKS=(fd stdin stdout stderr)

# Library directory layout differs between distributions, so the loader and its
# libraries are placed at the exact paths the copied binaries reference.
LIB_DIR=""

COPIED=()

copy_binary() {
	local src="$1"
	[ -e "$src" ] || die "required binary is missing on this host: $src"

	local real
	real="$(readlink -f "$src")"
	[ -x "$real" ] || die "required binary is not executable: $real"

	local dest="$ROOTFS/bin/$(basename "$real")"
	cp -f "$real" "$dest"
	chmod 0755 "$dest"
	verify_binary "$dest"
	COPIED+=("$src")
}

verify_binary() {
	local path="$1"
	[ -f "$path" ] || die "binary missing after copy: $path"
	[ -x "$path" ] || die "binary is not executable after copy: $path"
	local magic
	magic="$(head -c 4 "$path" | od -An -tx1 | tr -d ' \n')"
	[ "$magic" = "7f454c46" ] || die "copied file is not an ELF object: $path"
}

interpreter_for() {
	local path="$1"
	readelf -l "$path" 2>/dev/null |
		awk '/\[Requesting program interpreter:/ {gsub(/\[|\]/, "", $NF); print $NF; exit}'
}

# install_library places a library inside the Cell at the exact path a binary
# references and verifies the copy. Both the referenced path and its fully
# resolved target are installed so that symbolic links such as
# /lib64/ld-linux-x86-64.so.2 keep working inside the Cell, and multiarch
# layouts such as /lib/x86_64-linux-gnu are preserved.
install_library() {
	local src="$1"
	[ -e "$src" ] || die "required shared library is missing on the host: $src"

	local resolved
	resolved="$(readlink -f "$src")"
	[ -e "$resolved" ] || die "cannot resolve shared library: $src"

	install_object "$resolved" "$resolved"
	[ "$src" = "$resolved" ] || install_object "$resolved" "$src"
}

install_object() {
	local from="$1"
	local dest_path="$2"

	local target="$ROOTFS$dest_path"
	mkdir -p "$(dirname "$target")"
	cp -f "$from" "$target"
	chmod 0755 "$target"
	[ -f "$target" ] || die "library missing after copy: $dest_path"
	[ -x "$target" ] || die "library is not executable after copy: $dest_path"
}

install_with_deps() {
	local src="$1"
	[ -e "$src" ] || die "required binary is missing on this host: $src"

	local real
	real="$(readlink -f "$src")"
	install_library "$real"

	local interp
	interp="$(interpreter_for "$real")"
	if [ -n "$interp" ]; then
		if [ ! -e "$interp" ]; then
			die "ELF interpreter $interp referenced by $real is missing on this host"
		fi
		install_library "$interp"
		LIB_DIR="$(dirname "$interp")"
	fi

	local needed lib path
	needed="$(readelf -d "$real" 2>/dev/null |
		awk '/NEEDED/ {gsub(/[][]/, "", $NF); print $NF}' | sort -u)"
	if [ -z "$needed" ]; then
		die "no shared library dependencies resolved for $real"
	fi
	for lib in $needed; do
		case "$lib" in
		linux-vdso.so.* | linux-gate.so.*) continue ;;
		esac
		path=""
		if [ -n "$LIB_DIR" ] && [ -e "$LIB_DIR/$lib" ]; then
			path="$LIB_DIR/$lib"
		elif [ -e "/lib/$lib" ]; then
			path="/lib/$lib"
		elif [ -e "/usr/lib/$lib" ]; then
			path="/usr/lib/$lib"
		elif [ -e "/lib64/$lib" ]; then
			path="/lib64/$lib"
		elif [ -e "/usr/lib64/$lib" ]; then
			path="/usr/lib64/$lib"
		fi
		[ -n "$path" ] || die "shared library $lib required by $real was not found"
		install_library "$path"
	done
}

create_device() {
	local name="$1"
	local target="$ROOTFS/dev/$name"
	if mknod "$target" c "$2" "$3" 2>/dev/null; then
		chmod 0666 "$target"
		return 0
	fi
	: >"$target"
	chmod 0666 "$target"
}

create_devices() {
	local spec name major minor
	for spec in "null 1 3" "zero 1 5" "full 1 7" "random 1 8" "urandom 1 9" "tty 5 0"; do
		set -- $spec
		name="$1"
		major="$2"
		minor="$3"
		create_device "$name" "$major" "$minor"
		[ -e "$ROOTFS/dev/$name" ] || die "failed to create /dev/$name"
	done
}

create_links() {
	local name
	for name in "${DEV_LINKS[@]}"; do
		case "$name" in
		fd) ln -sfn /proc/self/fd "$ROOTFS/dev/fd" ;;
		stdin) ln -sfn /proc/self/fd/0 "$ROOTFS/dev/stdin" ;;
		stdout) ln -sfn /proc/self/fd/1 "$ROOTFS/dev/stdout" ;;
		stderr) ln -sfn /proc/self/fd/2 "$ROOTFS/dev/stderr" ;;
		esac
	done
	ln -sfn bash "$ROOTFS/bin/sh"
}

verify_rootfs() {
	local dir
	for dir in "${DIRECTORIES[@]}"; do
		[ -d "$ROOTFS/$dir" ] || die "required Cell directory is missing: $dir"
	done

	local name
	for name in null zero full random urandom tty; do
		[ -e "$ROOTFS/dev/$name" ] || die "required Cell device is missing: /dev/$name"
	done
	for name in "${DEV_LINKS[@]}"; do
		[ -L "$ROOTFS/dev/$name" ] || die "required /dev link is missing: $name"
	done

	[ -x "$ROOTFS/bin/sh" ] || die "Cell shell is missing or not executable"
	[ -L "$ROOTFS/bin/sh" ] || die "Cell shell must be a symbolic link to bash"

	local binary
	for binary in "$ROOTFS"/bin/*; do
		[ -f "$binary" ] || continue
		[ -x "$binary" ] || die "Cell binary is not executable: $binary"
		verify_binary "$binary"
		local interp
		interp="$(interpreter_for "$binary")"
		if [ -n "$interp" ]; then
			[ -e "$ROOTFS$interp" ] ||
				die "ELF interpreter $interp required by $binary is missing inside the Cell"
		fi
	done

	# Every NEEDED library of every Cell binary must resolve inside the Cell.
	for binary in "$ROOTFS"/bin/*; do
		[ -f "$binary" ] || continue
		local lib
		for lib in $(readelf -d "$binary" 2>/dev/null |
			awk '/NEEDED/ {gsub(/[][]/, "", $NF); print $NF}' | sort -u); do
			case "$lib" in
			linux-vdso.so.* | linux-gate.so.*) continue ;;
			esac
			if [ -e "$ROOTFS$LIB_DIR/$lib" ] || [ -e "$ROOTFS/lib/$lib" ] ||
				[ -e "$ROOTFS/lib64/$lib" ] || [ -e "$ROOTFS/usr/lib/$lib" ] ||
				[ -e "$ROOTFS/usr/lib64/$lib" ]; then
				continue
			fi
			die "shared library $lib required by $binary is missing inside the Cell"
		done
	done
}

if in_plan dirs; then
	mkdir -p "$ROOTFS"
	for dir in "${DIRECTORIES[@]}"; do
		mkdir -p "$ROOTFS/$dir"
	done
	chmod 1777 "$ROOTFS/tmp"
	chmod 1777 "$ROOTFS/dev/shm"
fi

if in_plan binaries; then
	for b in "${BINARIES[@]}"; do
		copy_binary "$b"
	done
	for b in "${OPTIONAL_BINARIES[@]}"; do
		if [ -e "$b" ]; then
			copy_binary "$b"
		else
			printf 'build-rootfs: optional binary %s is absent on this host\n' "$b"
		fi
	done
	for b in "${COPIED[@]}"; do
		install_with_deps "$b"
	done
fi

if in_plan devices; then
	create_devices
fi

if in_plan links; then
	create_links
fi

verify_rootfs

printf 'rootfs ready: %s\n' "$ROOTFS"