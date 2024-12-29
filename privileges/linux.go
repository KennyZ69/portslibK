package portslibK

import (
	"log"
	"os"
	"runtime"
)

// checks whether the current proccess has the CAP_NET_RAW capability or the user is root
func isPrivilegedLinux() bool {
	header := &CapUserHeader{
		Version: LINUX_CAP_VERSION_3,
		Pid:     uint32(os.Getpid()),
	}

	data := &CapUserData{}
	// lock the thread to prevent it from changing and having different pid afterwards
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	log.Printf("Checking capabilities for PID: %d", os.Getpid())

	// Get current capabilities
	if err := capget(header, data); err != nil {
		log.Printf("capget failed: %v", err)
		return os.Geteuid() == 0
	}

	// Add CAP_NET_RAW to inheritable set
	data.Inheritable = (1 << CAP_NET_RAW)

	if err := capset(header, data); err != nil {
		log.Printf("capset failed: %v", err)
		return os.Geteuid() == 0
	}

	log.Println("CAP_NET_RAW successfully set.")
	return true
}
