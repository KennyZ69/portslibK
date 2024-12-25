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
	var ofCount int = 0

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
			// Did not get a response so it shall retry and afterwards either determine correctly or return open|filtered
			log.Printf("Got no response, on %s retrying...\n", addr)
			_, err := UDPScan(targetIP, port, timeout)
			if err != nil {
				result.state = "open|filtered" // did not get a response so cannot determine whether it is actually closed
				ofCount++                      // adding to open|filtered count
				result.details = fmt.Sprintf("No response received on port: %d", port)
				log.Printf("%s is %s ... trying ACK Scan to determine\n", addr, result.state)
				// return result, fmt.Errorf(result.details)

				// TODO
				// now try again using ACK scan to determine if it is open or filtered
				// or I could make a map with port and its result.state and also make a count for open|filtered and if there's more than 1 of them, I would make an ACK scanner and range over those ports to scan for firewalls to determine between open and filtered

				ackS, err := NewACKScanner(targetIP, []int{port})
				if err != nil {
					result.details = fmt.Sprintf("%s\n-> Error after creating ACK Scanner: %v\n", result.details, err)
					return result, err
				}
				// ackS.targetPort = port
				r, err := ackS.Scan(port)
				if err != nil {
					result.details = fmt.Sprintf("%s -> Error after trying ACK Scan: %v\n", result.details, err)
					return result, err
				}
				// result.details = fmt.Sprintf("%s\nACK Scan detail: Port %d is %s\n", result.details, port, r)
				if r == string(AckUnfiltered) {
					result.details = fmt.Sprintf("%s\nACK Scan details: Port %d: %s -> %s\n", result.details, port, result.state, AckOpen)
					result.state = string(AckOpen)
				} else {
					result.details = fmt.Sprintf("%s\nACK Scan details: Port %d: %s -> %s\n", result.details, port, result.state, AckFiltered)
					result.state = string(AckFiltered)
				}
				return result, nil
			}
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
