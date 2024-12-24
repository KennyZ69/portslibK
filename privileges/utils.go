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

// Popular UDP payloads
var PortPayloads = map[int][]byte{
	53:  []byte("\x00\x01\x00\x00\x00\x00\x00\x00"),                             // DNS query payload
	123: []byte("\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00"),                     // NTP client request
	161: []byte("\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19"), // SNMP get request
}

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

// FetchPayload fetches the predefined payload for a specific port
func fetchPayload(port int) []byte {
	if p, ok := PortPayloads[port]; ok {
		return p
	}
	// default to empty payload if there's no predefined one
	return []byte{}
}
