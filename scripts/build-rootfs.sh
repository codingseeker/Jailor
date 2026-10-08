#!/usr/bin/env bash
set -euo pipefail

ROOTFS="${1:-rootfs}"
MODE="${2:-all}"

die() {
	printf 'build-rootfs: %s\n' "$*" >&2
	exit 1
}

note() {
	printf 'build-rootfs: %s\n' "$*"
}

require() {
	command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

for tool in readelf ldd cp mkdir chmod readlink find sort awk sed basename dirname; do
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

DIRECTORIES=(bin sbin lib lib64 usr/bin usr/sbin usr/lib etc tmp proc dev dev/pts dev/shm)

DEVICES=(null zero full random urandom tty)

DEV_LINKS=(fd stdin stdout stderr)

LIB_SEARCH_PATH=""

INSTALLED_LIBS="$ROOTFS/.jailor-installed-libs"

CELL_SHELL_BASENAME=""

add_search_dir() {
	local dir="$1"
	case ":$LIB_SEARCH_PATH:" in
	*":$dir:"*) return 0 ;;
	esac
	if [ -z "$LIB_SEARCH_PATH" ]; then
		LIB_SEARCH_PATH="$dir"
	else
		LIB_SEARCH_PATH="$LIB_SEARCH_PATH:$dir"
	fi
}

record_library() {
	local soname="$1" cell_path="$2"
	printf '%s\t%s\n' "$soname" "$cell_path" >>"$INSTALLED_LIBS"
}

verify_binary() {
	local path="$1"
	[ -f "$path" ] || die "file missing after copy: $path"
	[ -x "$path" ] || die "file is not executable after copy: $path"
	readelf -h "$path" >/dev/null ||
		die "copied file is not an ELF object: $path"
}

interpreter_for() {
	local path="$1" interp
	interp="$(readelf -l "$path" |
		awk '/\[Requesting program interpreter:/ {
			gsub(/\[|\]/, "", $NF)
			print $NF
			exit
		}')"
	if [ -z "$interp" ]; then
		die "no PT_INTERP program interpreter found in $path"
	fi
	printf '%s\n' "$interp"
}

needed_libraries() {
	local path="$1"
	readelf -d "$path" |
		awk '/NEEDED/ {
			gsub(/[][]/, "", $NF)
			print $NF
		}' | sort -u
}

loader_reported_paths() {
	local path="$1" output
	if ! output="$(ldd "$path" 2>&1)"; then
		printf '%s\n' "$output" >&2
		die "the host dynamic loader could not resolve the dependencies of $path"
	fi
	printf '%s\n' "$output" | awk '/=>/ {
		path = $3
		if (path ~ /^\//)
			print path
	}' | sort -u
}

loader_missing_dependencies() {
	local path="$1" output
	if ! output="$(ldd "$path" 2>&1)"; then
		printf '%s\n' "$output" >&2
		die "the host dynamic loader could not resolve the dependencies of $path"
	fi
	printf '%s\n' "$output" | awk '/=> not found/ { print $1 }' | sort -u
}

LDCONFIG_PATHS=""

cache_reported_paths() {
	if [ -z "$LDCONFIG_PATHS" ]; then
		if command -v ldconfig >/dev/null 2>&1; then
			LDCONFIG_PATHS="$(ldconfig -p)"
		else
			LDCONFIG_PATHS="unavailable"
		fi
	fi
	[ "$LDCONFIG_PATHS" != "unavailable" ] || return 0
	printf '%s\n' "$LDCONFIG_PATHS" | awk -v want="$1" '
		$1 == want && /^\t/ { print $NF }
	' | sort -u
}

install_object() {
	local from="$1"
	local dest_path="$2"
	local soname="${3:-}"

	[ -n "$from" ] || die "cannot install an object without a source path"
	[ -e "$from" ] || die "required shared library is missing on the host: $from"

	local target="$ROOTFS$dest_path"
	mkdir -p "$(dirname "$target")"
	cp -f "$from" "$target"
	chmod 0755 "$target"
	[ -f "$target" ] || die "library missing after copy: $dest_path"
	[ -x "$target" ] || die "library is not executable after copy: $dest_path"

	if [ -n "$soname" ]; then
		record_library "$soname" "$dest_path"
		add_search_dir "$(dirname "$dest_path")"
	fi
}

install_library() {
	local src="$1"
	local soname="${2:-}"

	[ -e "$src" ] || die "required shared library is missing on the host: $src"

	local resolved
	resolved="$(readlink -f "$src")"
	[ -e "$resolved" ] || die "cannot resolve shared library to an absolute path: $src"

	install_object "$resolved" "$resolved" "$soname"
	if [ "$src" != "$resolved" ]; then
		install_object "$resolved" "$src" "$soname"
	fi
}

copy_binary() {
	local src="$1"
	[ -e "$src" ] || die "required binary is missing on this host: $src"

	local real
	real="$(readlink -f "$src")"
	[ -e "$real" ] || die "cannot resolve binary to an absolute path: $src"
	[ -x "$real" ] || die "required binary is not executable: $real"

	local dest="$ROOTFS/bin/$(basename "$real")"
	cp -f "$real" "$dest"
	chmod 0755 "$dest"
	verify_binary "$dest"
	COPIED+=("$real")
}

install_with_deps() {
	local real="$1"
	[ -e "$real" ] || die "required binary is missing on this host: $real"

	local interpreter
	interpreter="$(interpreter_for "$real")"
	[ -e "$interpreter" ] ||
		die "ELF interpreter $interpreter referenced by $real is missing on this host"
	install_library "$interpreter" "$(basename "$interpreter")"

	local needed
	needed="$(needed_libraries "$real")"
	[ -n "$needed" ] || die "no shared library dependencies resolved for $real"

	local reported missing
	reported="$(loader_reported_paths "$real")"

	missing="$(loader_missing_dependencies "$real")"
	[ -z "$missing" ] ||
		die "the host dynamic loader could not find these libraries required by $real: $missing"

	local lib path
	for lib in $needed; do
		case "$lib" in
		linux-vdso.so.* | linux-gate.so.*) continue ;;
		esac
		path=""
		if [ -n "$reported" ]; then
			path="$(printf '%s\n' "$reported" | awk -v want="/$lib\$" '$0 ~ want { print; exit }')"
		fi
		if [ -z "$path" ]; then
			path="$(cache_reported_paths "$lib" | head -n 1)"
		fi
		[ -n "$path" ] ||
			die "shared library $lib required by $real was not found on this host"
		install_library "$path" "$lib"
	done

	for path in $reported; do
		install_library "$path" "$(basename "$path")"
	done
}

create_device() {
	local name="$1" major="$2" minor="$3"
	local target="$ROOTFS/dev/$name"
	if [ -e "$target" ] || [ -L "$target" ]; then
		chmod 0666 "$target"
		return 0
	fi
	local mknod_error=""
	if mknod_error="$(mknod "$target" c "$major" "$minor" 2>&1)"; then
		chmod 0666 "$target"
		return 0
	fi
	printf 'build-rootfs: mknod /dev/%s failed (%s); using a placeholder file\n' \
		"$name" "$mknod_error"
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

resolve_cell_shell() {
	if [ -n "$CELL_SHELL_BASENAME" ]; then
		return 0
	fi
	if [ -L "$ROOTFS/bin/sh" ]; then
		CELL_SHELL_BASENAME="$(basename "$(readlink "$ROOTFS/bin/sh")")"
		return 0
	fi
	die "cannot determine the Cell shell: $ROOTFS/bin/sh is missing"
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
	resolve_cell_shell
	[ -f "$ROOTFS/bin/$CELL_SHELL_BASENAME" ] ||
		die "the Cell shell binary is missing: /bin/$CELL_SHELL_BASENAME"
	ln -sfn "$CELL_SHELL_BASENAME" "$ROOTFS/bin/sh"
}

execute_cell_shell() {
	resolve_cell_shell
	local shell="$ROOTFS/bin/$CELL_SHELL_BASENAME"
	[ -x "$shell" ] || die "Cell shell is missing or not executable: $shell"

	local interpreter
	interpreter="$(interpreter_for "$shell")"
	[ -x "$ROOTFS$interpreter" ] ||
		die "the Cell ELF interpreter is missing or not executable: $interpreter"

	if [ -z "$LIB_SEARCH_PATH" ]; then
		die "no Cell library directory was populated"
	fi

	if ! "$ROOTFS$interpreter" --library-path "$LIB_SEARCH_PATH" "$shell" \
		-c 'printf "cell-shell-ok\n"' ; then
		die "the Cell shell cannot execute inside the Cell: /bin/sh -> $CELL_SHELL_BASENAME"
	fi
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

	resolve_cell_shell
	[ -L "$ROOTFS/bin/sh" ] || die "Cell shell must be a symbolic link to the copied shell"
	[ -e "$ROOTFS/bin/sh" ] || die "Cell shell /bin/sh is a dangling link: $CELL_SHELL_BASENAME"
	[ -x "$ROOTFS/bin/sh" ] || die "Cell shell /bin/sh is not executable"
	verify_binary "$ROOTFS/bin/$CELL_SHELL_BASENAME"

	local libc
	libc="$(find "$ROOTFS" -name 'libc.so.6*' -print)"
	[ -n "$libc" ] || die "no libc.so.6 was installed inside the Cell"

	local binary interpreter
	for binary in "$ROOTFS"/bin/*; do
		[ -f "$binary" ] || continue
		[ -x "$binary" ] || die "Cell binary is not executable: $binary"
		verify_binary "$binary"
		interpreter="$(interpreter_for "$binary")"
		[ -e "$ROOTFS$interpreter" ] ||
			die "ELF interpreter $interpreter required by $binary is missing inside the Cell"
	done

	if [ -n "$INSTALLED_LIBS" ] && [ -f "$INSTALLED_LIBS" ]; then
		local soname cell_path
		while IFS="$(printf '\t')" read -r soname cell_path; do
			[ -n "$soname" ] || continue
			[ -f "$ROOTFS$cell_path" ] ||
				die "shared library $soname is missing inside the Cell: $cell_path"
			[ -x "$ROOTFS$cell_path" ] ||
				die "shared library $soname is not executable inside the Cell: $cell_path"
		done <"$INSTALLED_LIBS"
	fi

	for binary in "$ROOTFS"/bin/*; do
		[ -f "$binary" ] || continue
		local lib
		for lib in $(needed_libraries "$binary"); do
			case "$lib" in
			linux-vdso.so.* | linux-gate.so.*) continue ;;
			esac
			local found
			found="$(find "$ROOTFS" -name "$lib" -print)"
			if [ -z "$found" ]; then
				die "shared library $lib required by $binary is missing inside the Cell"
			fi
		done
	done

	if in_plan binaries; then
		execute_cell_shell
	else
		note "binaries were not installed by this run; skipping the Cell shell execution check"
	fi

	rm -f "$INSTALLED_LIBS"
	INSTALLED_LIBS=""
}

COPIED=()

if in_plan dirs; then
	mkdir -p "$ROOTFS"
	for dir in "${DIRECTORIES[@]}"; do
		mkdir -p "$ROOTFS/$dir"
	done
	chmod 1777 "$ROOTFS/tmp"
	chmod 1777 "$ROOTFS/dev/shm"
fi

if in_plan binaries; then
	[ -n "$INSTALLED_LIBS" ] || : >"$INSTALLED_LIBS"

	for b in "${BINARIES[@]}"; do
		copy_binary "$b"
		if [ "$b" = "/bin/sh" ]; then
			CELL_SHELL_BASENAME="$(basename "$(readlink -f /bin/sh)")"
		fi
	done
	for b in "${OPTIONAL_BINARIES[@]}"; do
		if [ -e "$b" ]; then
			copy_binary "$b"
		else
			note "optional binary $b is absent on this host"
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

note "rootfs ready: $ROOTFS"
