package idmap

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"
)

type Range struct {
	Start uint32
	Size  uint32
}

func (r Range) Contains(id uint32) bool { return id >= r.Start && id < r.Start+r.Size }

func (r Range) After() uint32 { return r.Start + r.Size }

func (r Range) String() string {
	return fmt.Sprintf("%d-%d", r.Start, r.Start+r.Size-1)
}

type File string

const (
	SubUID File = "/etc/subuid"
	SubGID File = "/etc/subgid"
)

type Mapping struct {
	User  string
	Range Range
}
type Unavailable struct {
	File File
	User string
	Why  string
}

func (u *Unavailable) Error() string {
	return fmt.Sprintf("idmap: no subordinate ID range for user %q in %s (%s)",
		u.User, string(u.File), u.Why)
}

func IsUnavailable(err error) bool {
	var u *Unavailable
	return errors.As(err, &u)
}
func ParseFileBytes(name string, data []byte) ([]Mapping, error) {
	return parseReader(name, strings.NewReader(string(data)))
}

func ParseFile(f *os.File) ([]Mapping, error) {
	if f == nil {
		return nil, errors.New("idmap: nil file")
	}
	return parseReader(f.Name(), f)
}

func parseReader(name string, r io.Reader) ([]Mapping, error) {
	sc := bufio.NewScanner(r)
	line := 0
	var out []Mapping
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		parts := strings.Split(text, ":")
		if len(parts) != 3 {
			return nil, fmt.Errorf("idmap: %s:%d: malformed line %q (want USER:START:SIZE)", name, line, text)
		}
		start, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("idmap: %s:%d: bad START %q: %w", name, line, parts[1], err)
		}
		size, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("idmap: %s:%d: bad SIZE %q: %w", name, line, parts[2], err)
		}
		if start+size > uint64(^uint32(0))+1 {
			return nil, fmt.Errorf("idmap: %s:%d: range %d+%d exceeds the 32-bit ID space", name, line, start, size)
		}
		if size == 0 {
			out = append(out, Mapping{User: parts[0], Range: Range{uint32(start), 0}})
			continue
		}
		out = append(out, Mapping{User: parts[0], Range: Range{uint32(start), uint32(size)}})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("idmap: %s: %w", name, err)
	}
	return out, nil
}
func RangesFor(m []Mapping, user string) []Range {
	var out []Range
	for _, mp := range m {
		if mp.User == user && mp.Range.Size > 0 {
			out = append(out, mp.Range)
		}
	}
	return out
}
func PrimaryRange(m []Mapping, user string) *Range {
	rs := RangesFor(m, user)
	if len(rs) == 0 {
		return nil
	}
	r := rs[0]
	return &r
}
func LookupUsername(euid uint32) (string, error) {
	if u, err := user.LookupId(strconv.FormatUint(uint64(euid), 10)); err == nil {
		return u.Username, nil
	}
	return "", fmt.Errorf("idmap: no passwd entry for uid %d", euid)
}
func Lookup(file File, euid uint32) (string, []Range, error) {
	name := numericNameFromProc(euid)
	if name == "" {
		if u, err := user.LookupId(strconv.FormatUint(uint64(euid), 10)); err == nil {
			name = u.Username
		}
	}
	if name == "" {
		return "", nil, &Unavailable{
			File: file, User: strconv.FormatUint(uint64(euid), 10),
			Why: "no username resolution (uid not in passwd and not in /proc/self/status)",
		}
	}
	f, err := os.Open(string(file))
	if err != nil {
		return name, nil, &Unavailable{File: file, User: name, Why: "no subordinate-ID file: " + err.Error()}
	}
	defer f.Close()
	m, err := ParseFile(f)
	if err != nil {
		return name, nil, err
	}
	rs := RangesFor(m, name)
	if len(rs) == 0 {
		return name, nil, &Unavailable{File: file, User: name, Why: "no subordinate range entry"}
	}
	return name, rs, nil
}
func numericNameFromProc(euid uint32) string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return ""
	}
	want := "Uid:\t" + strconv.FormatUint(uint64(euid), 10)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, want) {
			break
		}
	}
	return ""
}
