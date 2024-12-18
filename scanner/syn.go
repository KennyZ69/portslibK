package scanner

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
)

type SynScanner struct {
	timeout  time.Duration
	sourceIP net.IP
	targetIP net.IP
	port     int   // possibly two options as for single port
	portR    []int // and for a port range
	ifi      *net.Interface
	options  gopacket.SerializeOptions
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
		portR:    portArr, // as in port range
		ifi:      ifi,
		options: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}, nil
}

// scan func should take a single port 'cause it will be ran in a loop and return report string with an error
func (s *SynScanner) Scan(portArr int) (string, error) {
	var report string

	return report, nil
}

func (s *SynScanner) Start() error {
	for i := 0; i < len(s.portR); i++ {
		s.port = s.portR[i] // this is just for the momentarly printing when stop func or so
		log.Printf("Starting SYN scan on %s:%d from %s\n", s.targetIP.String(), s.portR[i], s.sourceIP.String())
		// now run the scan, print results and errors
		report, err := s.Scan(s.port)
		if err != nil {
			log.Printf("Error in SYN scan on %s:%d -> %v\n", s.targetIP.String(), s.port, err)
		} else {
			log.Println(report)
		}
	}
	return nil
}

func (s *SynScanner) Stop() {
	log.Printf("Stopping SYN scan on addr %s\n", s.targetIP.String())
}
