package portslibK

import (
	"runtime"
)

var IsPrivileged bool = false

func isPrivileged() bool {
	// fmt.Println(runtime.GOOS)
	switch runtime.GOOS {
	case "windows":
		return isPrivilegedWin()
	case "linux":
		return isPrivilegedLinux()
	default:
		return false
	}
}

func Init() {
	IsPrivileged = isPrivileged()
}
