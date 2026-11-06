//go:build linux

package sysinfo

import (
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"strings"
)

// Processes reads /proc. Processes of other users are skipped when /proc
// does not let us read them.
func Processes() []Proc {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	self := os.Getpid()
	var out []Proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || len(raw) == 0 {
			continue
		}
		args := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
		exe, _ := os.Readlink("/proc/" + e.Name() + "/exe")
		out = append(out, Proc{PID: pid, Exe: exe, Args: args})
	}
	return out
}

// Listeners parses /proc/net/tcp and /proc/net/tcp6.
func Listeners() []Listener {
	owners := socketOwners()
	var out []Listener
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for _, ln := range lines[1:] {
			fs := strings.Fields(ln)
			if len(fs) < 10 || fs[3] != "0A" { // 0A = LISTEN
				continue
			}
			ipHex, portHex, ok := strings.Cut(fs[1], ":")
			if !ok {
				continue
			}
			port, err := strconv.ParseUint(portHex, 16, 32)
			if err != nil {
				continue
			}
			ip := parseHexIP(ipHex)
			if ip == nil {
				continue
			}
			l := Listener{IP: ip, Port: int(port)}
			if pid, ok := owners[fs[9]]; ok {
				l.PID = pid
				if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm"); err == nil {
					l.Proc = strings.TrimSpace(string(b))
				}
			}
			out = append(out, l)
		}
	}
	return out
}

// parseHexIP decodes the little-endian hex addresses used in /proc/net.
func parseHexIP(h string) net.IP {
	b, err := hex.DecodeString(h)
	if err != nil {
		return nil
	}
	switch len(b) {
	case 4:
		return net.IPv4(b[3], b[2], b[1], b[0])
	case 16:
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			for i := 0; i < 4; i++ {
				ip[w*4+i] = b[w*4+3-i]
			}
		}
		return ip
	}
	return nil
}

// socketOwners maps socket inodes to the pid that owns them. Only processes
// we are allowed to inspect show up.
func socketOwners() map[string]int {
	owners := map[string]int{}
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return owners
	}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		dir := "/proc/" + e.Name() + "/fd"
		fds, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(dir + "/" + fd.Name())
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			owners[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = pid
		}
	}
	return owners
}
