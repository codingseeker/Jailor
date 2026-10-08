//go:build linux

package jail

import (
	"errors"
	"io"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

type rawExec struct {
	path *byte
	argv []uintptr
	envp []uintptr
}

type rawInitPlan struct {
	launch       bool
	mountProc    bool
	noNewPrivs   bool
	seccompProg  []uintptr
	capMask      uint64
	readyFD      int
	prisonerFD   int
	goFD         int
	prisonerRead int
	inheritedFD  []int
	prisoner     rawExec
	init         rawExec
}

var initPlan rawInitPlan

func newRawExec(argv, env []string) (rawExec, error) {
	if len(argv) == 0 {
		return rawExec{}, errors.New("jail: empty command")
	}
	spec := rawExec{argv: make([]uintptr, 0, len(argv)+1), envp: make([]uintptr, 0, len(env)+1)}
	ptrs := make([]*byte, 0, len(argv)+len(env)+1)
	for _, arg := range argv {
		p, err := syscall.BytePtrFromString(arg)
		if err != nil {
			return rawExec{}, err
		}
		ptrs = append(ptrs, p)
		spec.argv = append(spec.argv, uintptr(unsafe.Pointer(p)))
	}
	spec.argv = append(spec.argv, 0)
	for _, e := range env {
		p, err := syscall.BytePtrFromString(e)
		if err != nil {
			return rawExec{}, err
		}
		ptrs = append(ptrs, p)
		spec.envp = append(spec.envp, uintptr(unsafe.Pointer(p)))
	}
	spec.envp = append(spec.envp, 0)
	if len(ptrs) > 0 {
		spec.path = ptrs[0]
	}
	return spec, nil
}

var (
	rawStrProc      = []byte("proc\x00")
	rawStrSlashProc = []byte("/proc\x00")
	rawStrEmpty     = []byte("\x00")
	rawDigits       = []byte("0123456789")
)

const (
	stepMountProc = iota
	stepNoNewPrivs
	stepSeccomp
	stepCapabilities
	stepFork
	stepExecPrisoner
	stepExecInit
)

var rawSteps = [...][]byte{
	stepMountProc:    []byte("mount /proc\x00"),
	stepNoNewPrivs:   []byte("set no_new_privs\x00"),
	stepSeccomp:      []byte("install seccomp filter\x00"),
	stepCapabilities: []byte("apply capability policy\x00"),
	stepFork:         []byte("fork prisoner\x00"),
	stepExecPrisoner: []byte("exec prisoner\x00"),
	stepExecInit:     []byte("exec jail init\x00"),
}

var rawErrnos = map[syscall.Errno][]byte{
	syscall.EPERM:      []byte("operation not permitted\x00"),
	syscall.ENOENT:     []byte("no such file or directory\x00"),
	syscall.EACCES:     []byte("permission denied\x00"),
	syscall.EEXIST:     []byte("file exists\x00"),
	syscall.ENODEV:     []byte("no such device\x00"),
	syscall.ENOTDIR:    []byte("not a directory\x00"),
	syscall.EISDIR:     []byte("is a directory\x00"),
	syscall.EINVAL:     []byte("invalid argument\x00"),
	syscall.ENOEXEC:    []byte("exec format error\x00"),
	syscall.ENOMEM:     []byte("cannot allocate memory\x00"),
	syscall.EAGAIN:     []byte("resource temporarily unavailable\x00"),
	syscall.ELOOP:      []byte("too many levels of symbolic links\x00"),
	syscall.ENOSPC:     []byte("no space left on device\x00"),
	syscall.EBADF:      []byte("bad file descriptor\x00"),
	syscall.EFAULT:     []byte("bad address\x00"),
	syscall.E2BIG:      []byte("argument list too long\x00"),
	syscall.EIO:        []byte("input/output error\x00"),
	syscall.EMFILE:     []byte("too many open files\x00"),
	syscall.ENOSYS:     []byte("function not implemented\x00"),
	syscall.EXDEV:      []byte("invalid cross-device link\x00"),
	syscall.EROFS:      []byte("read-only file system\x00"),
	syscall.ETXTBSY:    []byte("text file busy\x00"),
	syscall.EOPNOTSUPP: []byte("operation not supported\x00"),
}

//go:nosplit
//go:norace
func rawWrite(fd int, b []byte) syscall.Errno {
	if len(b) == 0 {
		return 0
	}
	_, _, e := syscall.RawSyscall(syscall.SYS_WRITE, uintptr(fd),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return e
}

//go:nosplit
//go:norace
func rawFork() int {
	r, _, e := syscall.RawSyscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
	if e != 0 {
		return -int(e)
	}
	return int(r)
}

//go:nosplit
//go:norace
func rawExit(code int) {
	syscall.RawSyscall(syscall.SYS_EXIT_GROUP, uintptr(code), 0, 0)
	syscall.RawSyscall(syscall.SYS_EXIT, uintptr(code), 0, 0)
	for {
	}
}

type rawSockFprog struct {
	len    uint16
	filter *uintptr
}

//go:nosplit
//go:norace
func rawRead(fd int, buf []byte) {
	if len(buf) == 0 {
		return
	}
	_, _, _ = syscall.RawSyscall(syscall.SYS_READ, uintptr(fd),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
}

//go:nosplit
//go:norace
func rawNoNewPrivs() syscall.Errno {
	const prSetNoNewPrivs = 38
	_, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(prSetNoNewPrivs), 1, 0, 0, 0, 0)
	return e
}

//go:nosplit
//go:norace
func rawDropBoundingCap(cap int) syscall.Errno {
	const prCapBSetDrop = 24
	_, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, uintptr(prCapBSetDrop), uintptr(cap), 0, 0, 0, 0)
	return e
}

//go:nosplit
//go:norace
func rawDropCapabilities(mask uint64) syscall.Errno {
	for cap := 0; cap < capCount; cap++ {
		if mask&(1<<uint(cap)) != 0 {
			continue
		}
		if e := rawDropBoundingCap(cap); e != 0 {
			return e
		}
	}
	var current [2]rawCapData
	hdr := rawCapHeader{version: capVersion3}
	_, _, e := syscall.RawSyscall(syscall.SYS_CAPGET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&current[0])), 0)
	if e != 0 {
		return e
	}
	words := [2]rawCapData{
		{
			effective:   current[0].effective & uint32(mask),
			permitted:   current[0].permitted & uint32(mask),
			inheritable: current[0].inheritable & uint32(mask),
		},
		{
			effective:   current[1].effective & uint32(mask>>32),
			permitted:   current[1].permitted & uint32(mask>>32),
			inheritable: current[1].inheritable & uint32(mask>>32),
		},
	}
	set := rawCapHeader{version: capVersion3}
	_, _, e = syscall.RawSyscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&set)), uintptr(unsafe.Pointer(&words[0])), 0)
	return e
}

//go:nosplit
//go:norace
func rawInstallSeccomp(prog []uintptr) syscall.Errno {
	if len(prog) == 0 {
		return syscall.EINVAL
	}
	fprog := rawSockFprog{len: uint16(len(prog)), filter: &prog[0]}
	_, _, e := syscall.RawSyscall6(syscallSYS_SECCOMP, seccompSetModeFilter, 0,
		uintptr(unsafe.Pointer(&fprog)), 0, 0, 0)
	return e
}

//go:nosplit
//go:norace
func rawMount(source *byte, target *byte, fstype *byte, flags uintptr, data *byte) syscall.Errno {
	_, _, e := syscall.RawSyscall6(syscall.SYS_MOUNT, uintptr(unsafe.Pointer(source)),
		uintptr(unsafe.Pointer(target)), uintptr(unsafe.Pointer(fstype)), flags,
		uintptr(unsafe.Pointer(data)), 0)
	return e
}

//go:nosplit
//go:norace
func rawSetpgid() {
	syscall.RawSyscall(syscall.SYS_SETPGID, 0, 0, 0)
}

//go:nosplit
//go:norace
func rawTryExec(spec *rawExec) {
	if spec.path == nil || len(spec.argv) == 0 || len(spec.envp) == 0 {
		rawExit(127)
	}
	syscall.RawSyscall6(syscall.SYS_EXECVE, uintptr(unsafe.Pointer(spec.path)),
		uintptr(unsafe.Pointer(&spec.argv[0])), uintptr(unsafe.Pointer(&spec.envp[0])),
		0, 0, 0)
	rawExit(127)
}

//go:nosplit
//go:norace
func rawAppend(msg *[128]byte, n int, s []byte) int {
	for _, c := range s {
		if c == 0 || n >= len(msg) {
			break
		}
		msg[n] = c
		n++
	}
	return n
}

//go:nosplit
//go:norace
func rawAppendInt(msg *[128]byte, n int, v int) int {
	var digits [12]byte
	m := 0
	if v == 0 {
		digits[0] = '0'
		m = 1
	}
	for v > 0 && m < len(digits) {
		digits[m] = rawDigits[v%10]
		v /= 10
		m++
	}
	for i := m - 1; i >= 0 && n < len(msg); i-- {
		msg[n] = digits[i]
		n++
	}
	return n
}

//go:nosplit
//go:norace
func rawReportFailure(fd int, step int, errno syscall.Errno) {
	var msg [128]byte
	n := rawAppend(&msg, 0, []byte("Fjail init: "))
	if step >= 0 && step < len(rawSteps) {
		n = rawAppend(&msg, n, rawSteps[step])
	}
	n = rawAppend(&msg, n, []byte(": "))
	if text, ok := rawErrnos[errno]; ok {
		n = rawAppend(&msg, n, text)
	} else {
		n = rawAppend(&msg, n, []byte("errno "))
		n = rawAppendInt(&msg, n, int(errno))
	}
	if n < len(msg) {
		msg[n] = '\n'
		n++
	}
	_ = rawWrite(fd, msg[:n])
	_ = rawWrite(2, msg[:n])
}

//go:nosplit
//go:norace
func rawReportReady(fd int, pid int) {
	var msg [128]byte
	msg[0] = syncReady
	n := rawAppendInt(&msg, 1, pid)
	if n < len(msg) {
		msg[n] = '\n'
		n++
	}
	_ = rawWrite(fd, msg[:n])
}

//go:nosplit
//go:norace
func rawReportPID(fd int, pid int) {
	var msg [128]byte
	n := rawAppendInt(&msg, 0, pid)
	if n < len(msg) {
		msg[n] = '\n'
		n++
	}
	_ = rawWrite(fd, msg[:n])
}

const (
	sigBlock   = 0
	sigUnblock = 1
	sigSetSize = 8
)

func rawSupervisorSignals() [sigSetSize]byte {
	var set [sigSetSize]byte
	for _, sig := range []uint32{
		uint32(syscall.SIGTERM),
		uint32(syscall.SIGINT),
		uint32(syscall.SIGQUIT),
		uint32(syscall.SIGHUP),
	} {
		set[sig/8] |= 1 << (sig % 8)
	}
	return set
}

func rawBlockSupervisorSignals() {
	set := rawSupervisorSignals()
	syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigBlock,
		uintptr(unsafe.Pointer(&set[0])), 0, uintptr(sigSetSize), 0, 0)
}

func rawUnblockSupervisorSignals() {
	set := rawSupervisorSignals()
	syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, sigUnblock,
		uintptr(unsafe.Pointer(&set[0])), 0, uintptr(sigSetSize), 0, 0)
}

//go:nosplit
//go:norace
func rawClose(fd int) {
	if fd >= 0 {
		syscall.RawSyscall(syscall.SYS_CLOSE, uintptr(fd), 0, 0)
	}
}

//go:nosplit
//go:norace
func rawPID1Main() {
	plan := &initPlan
	if !plan.launch {
		rawExit(127)
	}
	if plan.goFD >= 0 {
		var marker [8]byte
		rawRead(plan.goFD, marker[:1])
		rawClose(plan.goFD)
	}
	plan.closeInherited()

	if plan.mountProc {
		if e := rawMount(&rawStrProc[0], &rawStrSlashProc[0], &rawStrProc[0],
			uintptr(syscall.MS_NOSUID|syscall.MS_NODEV|syscall.MS_NOEXEC), &rawStrEmpty[0]); e != 0 {
			rawReportFailure(plan.readyFD, stepMountProc, e)
			rawExit(127)
		}
	}
	if plan.noNewPrivs {
		if e := rawNoNewPrivs(); e != 0 {
			rawReportFailure(plan.readyFD, stepNoNewPrivs, e)
			rawExit(127)
		}
	}
	if len(plan.seccompProg) > 0 {
		if e := rawInstallSeccomp(plan.seccompProg); e != 0 {
			rawReportFailure(plan.readyFD, stepSeccomp, e)
			rawExit(127)
		}
	}
	if e := rawDropCapabilities(plan.capMask); e != 0 {
		rawReportFailure(plan.readyFD, stepCapabilities, e)
		rawExit(127)
	}
	pid := rawFork()
	if pid == 0 {
		plan.closeAll()
		rawSetpgid()
		rawTryExec(&plan.prisoner)
	}
	if pid < 0 {
		rawReportFailure(plan.readyFD, stepFork, syscall.Errno(-pid))
		rawExit(127)
	}
	rawReportReady(plan.readyFD, pid)
	if plan.prisonerFD >= 0 {
		rawReportPID(plan.prisonerFD, pid)
	}
	rawClose(plan.readyFD)
	rawClose(plan.prisonerFD)
	rawBlockSupervisorSignals()
	rawTryExec(&plan.init)
	rawReportFailure(plan.readyFD, stepExecInit, syscall.ENOENT)
	rawExit(127)
}

//go:noinline
func spawnRawInit() int {
	var reserve [32 << 10]byte
	if initPlan.launch {
		reserve[0] = 1
	} else {
		reserve[0] = 0
	}
	reserve[len(reserve)-1] = reserve[0]
	runtime.KeepAlive(&reserve)
	pid := rawFork()
	if pid == 0 {
		rawPID1Main()
	}
	return pid
}

func readAllFile(f *os.File) ([]byte, error) {
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func runtimeLockThread() {
	runtime.LockOSThread()
}

func (p *rawInitPlan) closeInherited() {
	for _, fd := range p.inheritedFD {
		if fd >= 0 && fd != p.readyFD && fd != p.prisonerFD && fd != p.prisonerRead {
			rawClose(fd)
		}
	}
}

func (p *rawInitPlan) closeAll() {
	for _, fd := range p.inheritedFD {
		rawClose(fd)
	}
}
