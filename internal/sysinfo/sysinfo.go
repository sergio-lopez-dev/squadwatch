// Package sysinfo lists running processes and listening TCP ports without
// running any third-party code.
package sysinfo

import (
	"net"
	"path/filepath"
	"strings"
)

// Proc is a running process.
type Proc struct {
	PID  int
	Exe  string
	Args []string
}

// Base is the name of the program, taken from argv[0].
func (p Proc) Base() string {
	if len(p.Args) > 0 && p.Args[0] != "" {
		return filepath.Base(p.Args[0])
	}
	return filepath.Base(p.Exe)
}

// Line is the full command line.
func (p Proc) Line() string { return strings.Join(p.Args, " ") }

// Listener is a listening TCP socket.
type Listener struct {
	IP   net.IP
	Port int
	PID  int
	Proc string
}

// Public reports whether other machines can reach the socket.
func (l Listener) Public() bool { return !l.IP.IsLoopback() }
