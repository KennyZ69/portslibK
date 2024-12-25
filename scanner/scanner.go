package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/KennyZ69/portslibK/privileges"
)

// I guess I can do it as an interface because there will be more types of scans in the future and all of them should have the Scan func and also start stop
type Scanner interface {
	Start() error
	Stop()
	Scan(int) (string, error) // maybe add semaphore chan to this ??
	// *net.Interface
}

func CreateScanner(sType string, targetIP net.IP, portArr []int, timeout time.Duration) (Scanner, error) {
	switch strings.ToLower(sType) {
	case "syn", "sS":
		// Check if the user is privileged
		if !privileges.IsPrivileged {
			return nil, fmt.Errorf("Access denied: You must run this as a privileged user.\n")
		}
		s, err := NewSynScanner(timeout, targetIP, portArr)
		return s, err
	case "tcp", "connect", "cS", "tcpS":
		s, err := NewTCPScanner(timeout, targetIP, portArr)
		return s, err
	case "udp", "uS":
		s, err := NewUDPScanner(timeout, targetIP, portArr)
		return s, err
	case "ack", "aS", "acS", "ackS":
		s, err := NewACKScanner(targetIP, portArr)
		return s, err
	}

	return nil, fmt.Errorf("Error getting a scanner")
}
