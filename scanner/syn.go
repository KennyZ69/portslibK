package portslibK

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/phayes/freeport"
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

	// get a free system port for the syn packet later
	srcPort, err := freeport.GetFreePort()
	if err != nil {
		return fmt.Sprintf("Could not get a free system port\n"), fmt.Errorf("Error getting a free port: %v\n", err)
	}

	mac, err := s.GetMac() // this keeps timing out
	if err != nil {
		return "Could not get hardware addr\n", fmt.Errorf("Error getting mac addr: %v\n", err)
	}

	// build and send the layers as a sigle packet on a network
	p, err := s.BuildSYNPacket(uint16(srcPort), s.ifi, mac)
	if err != nil {
		return fmt.Sprintf("Could not build syn packet for port %d\n", port), err
	}

	if err = handle.WritePacketData(p); err != nil {
		return fmt.Sprintf("Error sending packet data for port %d\n", port), err
	}

	eth := &layers.Ethernet{}
	ip4 := &layers.IPv4{}
	tcp := &layers.TCP{}
	//
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, eth, ip4, tcp)

	ipFlow := gopacket.NewFlow(layers.EndpointIPv4, s.targetIP, s.sourceIP)

	// pSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	//
	// timeout := time.After(5 * time.Second)
	// pChan := pSrc.Packets()
	//
	// // TODO: Now I have to work on this... the GetMac func keeps timing out but I can resolve that later
	// // it would be better now to make this scan functionality correct
	// for {
	// 	select {
	// 	case packet, ok := <-pChan:
	// 		if !ok {
	// 			log.Println("Packet channel closed")
	// 			return fmt.Sprintf("No response for port %d\n", port), nil
	// 		}
	// 		log.Println("Packet received")
	// 		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	// 			log.Println("TCP Layer found")
	// 			tcp := tcpLayer.(*layers.TCP)
	// 			if tcp.SrcPort == layers.TCPPort(port) && tcp.SYN && tcp.ACK {
	// 				resp := fmt.Sprintf("Port %d is open on %s\n", port, s.targetIP)
	// 				log.Printf(resp)
	// 				return resp, nil
	// 			}
	// 		}
	// 	case <-timeout:
	// 		log.Println("Timeout reached, no packets received")
	// 		return fmt.Sprintf("No response for port %d within timeout period\n", port), fmt.Errorf("Timeout reached\n")
	// 	default:
	// 	}
	// 	break
	// }

	for {
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			// return fmt.Sprintf("Timeout on port %d\n", port), nil
			log.Printf("Timeout on port %d\n", port)
			break

		} else if err == io.EOF {
			break
		} else if err != nil {
			// return fmt.Sprintf("Error reading packet data for port %d\n", port), err
			log.Printf("Error reading packet data for port %d\n", port) // port is closed
			continue
		}

		// decode the packet
		decoded := []gopacket.LayerType{}
		if err := parser.DecodeLayers(data, &decoded); err != nil {
			// return fmt.Sprintf("Error decoding packet for port %d\n", port), err
			log.Printf("Error decoding packet for port %d\n", port)
			continue
		}

		for _, layerType := range decoded {
			switch layerType {
			case layers.LayerTypeIPv4:
				if ip4.NetworkFlow() != ipFlow {
					continue
				}
			case layers.LayerTypeTCP:
				if tcp.DstPort != layers.TCPPort(srcPort) {
					continue
				} else if tcp.SYN && tcp.ACK {
					report = fmt.Sprintf("Port %d is open on %s\n", port, s.targetIP)
					log.Printf(report)
					return report, nil
				} else if tcp.RST {
					report = fmt.Sprintf("Port %d is closed on %s\n", port, s.targetIP)
					log.Printf(report)
					return report, nil
				}
			default:
				return report, fmt.Errorf("Unexpected layer type: %v\n", layerType)
			}
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
				log.Printf("Error in SYN scan on %s:%d -> %v\nRetrying with a whole TCP connect scan\n", s.targetIP.String(), s.port, err)
				// retry with tcp connect scan
				// basically I want to run the syn scanner but if it fails, I want it to retry using the whole tcp connection but
				// I should have functions for both of them to maybe use a bit different way in goapt

				sm := make(chan struct{}, ulimit())
				rStr, err = TCPScan(s.targetIP, s.port, sm)
				if err != nil {
					log.Printf("Error in TCP scan on %s:%d -> %v\n", s.targetIP.String(), s.port, err)
					report <- rStr
					return
				}
				report <- rStr
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
