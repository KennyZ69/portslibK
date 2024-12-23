package privileges

import (
	"syscall"
	"unsafe"
)

const (
	LINUX_CAP_VERSION_1 = 0x19980330
	LINUX_CAP_VERSION_2 = 0x20071026
	LINUX_CAP_VERSION_3 = 0x20080522
	CAP_NET_RAW         = 13
)

type CapUserHeader struct {
	Version uint32
	Pid     uint32
}

type CapUserData struct {
	Effective   uint32
	Permitted   uint32
	Inheritable uint32
}

// Because the golang unix package does not have the structs and functions defined for the capabilities system I had to define them myself to be used to get the privileges

func capget(header *CapUserHeader, data *CapUserData) error {
	_, _, errn := syscall.Syscall(syscall.SYS_CAPGET, uintptr(unsafe.Pointer(header)), uintptr(unsafe.Pointer(data)), 0)
	if errn != 0 {
		return syscall.Errno(errn)
	}
	return nil
}

func capset(header *CapUserHeader, data *CapUserData) error {
	_, _, errn := syscall.Syscall(syscall.SYS_CAPSET, uintptr(unsafe.Pointer(header)), uintptr(unsafe.Pointer(data)), 0)
	if errn != 0 {
		return syscall.Errno(errn)
	}
	return nil
}
