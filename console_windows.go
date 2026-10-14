//go:build windows

package main

import "syscall"

// Switch the Windows console to UTF-8 so dashes and arrows print correctly.
func init() {
	k := syscall.NewLazyDLL("kernel32.dll")
	k.NewProc("SetConsoleOutputCP").Call(65001)
}
