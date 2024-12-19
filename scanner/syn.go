package scanner

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	// fmt.Println(soureIP.String(), ifi)

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
func (s *SynScanner) Scan(port int) (string, error) {
	var report string

	// log.Printf("Using interface: %s\n", s.ifi.Name)
	handle, err := pcap.OpenLive(s.ifi.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return fmt.Sprintf("Could not handle port %d\n", port), err
	}
	defer handle.Close()

	// Apply a BPF filter to capture only TCP packets to the target IP and port
	filter := fmt.Sprintf("tcp and dst host %s and dst port %d", s.targetIP.String(), port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Sprintf("Failed to set BPF filter for port %d\n", port), err
	}

	p, err := BuildSYNPacket(s.sourceIP, s.targetIP, 54321, uint16(s.port))
	if err != nil {
		return fmt.Sprintf("Could not build syn packet for port %d\n", port), err
	}

	if err = handle.WritePacketData(p); err != nil {
		return fmt.Sprintf("Error sending packet data for port %d\n", port), err
	}

	// listen for responses
	pSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	// for pack := range pSrc.Packets() {
	// 	if tcpLayer := pack.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	// 		tcp := tcpLayer.(*layers.TCP)
	// 		if tcp.SrcPort == layers.TCPPort(s.port) && tcp.SYN && tcp.ACK {
	// 			resp := fmt.Sprintf("Port %d is open on %s\n", port, s.targetIP)
	// 			log.Printf(resp)
	// 			report = resp
	// 			break
	// 		}
	// 	}
	// }

	timeout := time.After(5 * time.Second)
	pChan := pSrc.Packets()

	for {
		select {
		case packet, ok := <-pChan:
			if !ok {
				log.Println("Packet channel closed")
				return fmt.Sprintf("No response for port %d\n", port), nil
			}
			log.Println("Packet received")
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				log.Println("TCP Layer found")
				tcp := tcpLayer.(*layers.TCP)
				if tcp.SrcPort == layers.TCPPort(port) && tcp.SYN && tcp.ACK {
					resp := fmt.Sprintf("Port %d is open on %s\n", port, s.targetIP)
					log.Printf(resp)
					return resp, nil
				}
			}
		case <-timeout:
			log.Println("Timeout reached, no packets received")
			// break
			return fmt.Sprintf("No response for port %d within timeout period\n", port), fmt.Errorf("Timeout reached\n")
		}
		break
	}
	log.Println("Ending the scan ... ")

	return report, nil
}

func (s *SynScanner) Start() error {
	var wg sync.WaitGroup

	// channel for result reports of a scan
	report := make(chan string, len(s.portR))

	// start the scan
	fmt.Println("Starting ... ")
	wg.Add(1)
	for i := 0; i < len(s.portR); i++ {
		log.Printf("Starting SYN scan on %s:%d from %s\n", s.targetIP.String(), s.portR[i], s.sourceIP.String())
		go func(i int) {
			defer wg.Done()
			s.port = s.portR[i] // this is just for the momentarly printing when stop func or so
			// now run the scan, print results and errors
			rStr, err := s.Scan(s.port)
			if err != nil {
				log.Printf("Error in SYN scan on %s:%d -> %v\n", s.targetIP.String(), s.port, err)
				return
			}

			report <- rStr
			return
		}(i)
	}

	go func() {
		wg.Wait()
		close(report)
	}()

	// print out the results
	for r := range report {
		fmt.Println(r)
	}
	return nil
}

func (s *SynScanner) Stop() {
	log.Printf("Stopping SYN scan on addr %s\n", s.targetIP.String())
}
