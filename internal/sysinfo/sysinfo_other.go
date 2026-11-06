//go:build !linux

package sysinfo

import (
	"os/exec"
	"strconv"
	"strings"
)

// Processes uses the system ps on macOS and other Unix systems.
func Processes() []Proc {
	out, err := exec.Command("ps", "-axo", "pid=,args=").Output()
	if err != nil {
		return nil
	}
	var procs []Proc
	for _, ln := range strings.Split(string(out), "\n") {
		ln = strings.TrimSpace(ln)
		pidStr, rest, ok := strings.Cut(ln, " ")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		args := strings.Fields(rest)
		procs = append(procs, Proc{PID: pid, Args: args})
	}
	return procs
}

// Listeners is not implemented outside Linux yet.
func Listeners() []Listener { return nil }
