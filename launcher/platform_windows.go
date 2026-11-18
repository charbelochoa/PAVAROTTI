package main

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func prepare(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

func showError(message string) {
	body, _ := syscall.UTF16PtrFromString(message)
	title, _ := syscall.UTF16PtrFromString("PAVAROTTI")
	box := syscall.NewLazyDLL("user32.dll").NewProc("MessageBoxW")
	box.Call(0, uintptr(unsafe.Pointer(body)), uintptr(unsafe.Pointer(title)), 0x10)
}
