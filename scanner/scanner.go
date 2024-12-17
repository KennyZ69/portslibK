package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// I guess I can do it as an interface because there will be more types of scans in the future and all of them should have the Scan func and also start stop
type Scanner interface {
	Start() error
	Stop()
	Scan([]int) (string, error) // maybe add semaphore chan to this ??
	// *net.Interface
}

type SynScanner struct {
	timeout  time.Duration
	sourceIP net.IP
	targetIP net.IP
	// port int
	port []int
	ifi  *net.Interface
}

func NewSynScanner(timeout time.Duration, targetIP net.IP, portArr []int) (*SynScanner, error) {
	soureIP, ifi, err := GetSource(targetIP)
	if err != nil {
		return nil, fmt.Errorf("Error creating new SYN scanner: %v\n", err)
	}

	return &SynScanner{
		timeout:  timeout,
		sourceIP: soureIP,
		targetIP: targetIP,
		port:     portArr,
		ifi:      ifi,
	}, nil
}

func (s *SynScanner) Start() error {

}

func CreateScanner(sType string, timeout time.Duration) (Scanner, error) {
	switch strings.ToLower(sType) {
	case "syn":
		if os.Geteuid() == 0 {

		}
	}
}
