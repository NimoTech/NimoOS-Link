//go:build !linux

package main

import (
	"errors"
	"io"
)

// The tunnel itself (TUN device, routes, the pid file) is Linux only for
// now; pair still works here, so a pairing can be prepared on any Unix.
var errLinuxOnly = errors.New("the tunnel runs on Linux only for now")

func runUp(Config, string, bool, string, []string, io.Writer) error { return errLinuxOnly }

func runStatus() error { return errLinuxOnly }

func runDown() error { return errLinuxOnly }
