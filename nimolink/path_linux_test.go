//go:build linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A path file left by a killed `up` is gone before the next one starts
// looking: status never shows another process's path.
func TestClearPathRemovesALeftover(t *testing.T) {
	old := pathFile
	pathFile = filepath.Join(t.TempDir(), "nimolink.path")
	defer func() { pathFile = old }()
	setPath(Path{"stun", "203.0.113.7:51446"})
	clearPath()
	if _, err := os.Stat(pathFile); !os.IsNotExist(err) {
		t.Fatalf("leftover still there: %v", err)
	}
	if currentPath() != (Path{}) {
		t.Fatalf("in-process path still %v", currentPath())
	}
}
