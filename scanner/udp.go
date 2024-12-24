package scanner

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type UDPScanner struct {
	// listeningAddr string // address to receive responses
	targetIP net.IP
	timeout  time.Duration
	portR    []int
	port     int
	results  chan UDPResult
	// results []UDPResult
}

type UDPResult struct {
	port    int
	state   string
	version string
	details string
}

func NewUDPScanner(timeout time.Duration, targetIP net.IP, portArr []int) (*UDPScanner, error) {
	return &UDPScanner{
		targetIP: targetIP,
		portR:    portArr,
		timeout:  timeout,
		results:  make(chan UDPResult),
	}, nil
}

func (s *UDPScanner) Start() error {
	log.Println("Starting UDP scanner...")
	var wg sync.WaitGroup

	report := make(chan string, len(s.portR))

	wg.Add(1)
	for i := 0; i < len(s.portR); i++ {
		log.Printf("Starting UDP scan on %s:%d\n", s.targetIP.String(), s.portR[i])
		go func(i int) {
			defer wg.Done()
			s.port = s.portR[i]
			r, err := s.Scan(s.port)
			if err != nil {
				log.Printf("Error in UDP scan on %s:%d -> %v\n", s.targetIP.String(), s.port, err)
			}

			report <- r
			return
		}(i)
	}

	go func() {
		wg.Wait()
		close(report)
	}()

	for r := range report {
		log.Println(r)
	}

	return nil
}

func (s *UDPScanner) Stop() {
	log.Println("Stopping UDP scanner...")
	return
}

func (s *UDPScanner) Scan(port int) (string, error) {
	r, err := UDPScan(s.targetIP, port, s.timeout)
	report := r.MakeReport()
	return report, err
}

func UDPScan(targetIP net.IP, port int, timeout time.Duration) (*UDPResult, error) {
	result := &UDPResult{
		port: port,
	}

	addr := fmt.Sprintf("%s:%d", targetIP.String(), port)
	c, err := net.DialTimeout("udp", addr, timeout)
	if err != nil {
		result.state = "closed"
		result.details = fmt.Sprintf("Error dialing %s: %v", addr, err)
		return result, err
	}
	defer c.Close()

	p := fetchPayload(port)

	_, err = c.Write(p)
	if err != nil {
		result.state = "closed"
		result.details = fmt.Sprintf("Error writing to %s: %v", addr, err)
		return result, err
	}

	c.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			result.state = "open|filtered" // did not get a response so cannot determine whether it is actually closed
			result.details = fmt.Sprintf("No response received on port: %d", port)
			return result, fmt.Errorf(result.details)
		}
		result.state = "closed"
		result.details = fmt.Sprintf("Error reading from %s: %v", addr, err)
		return result, fmt.Errorf(result.details)
	}

	result.state = "open"
	result.details = fmt.Sprintf("Received %d bytes from %s", n, addr)

	return result, nil
}

func (r *UDPResult) MakeReport() string {
	return fmt.Sprintf("\nPort %d: %s\nDetails: %s", r.port, r.state, r.details)
}
