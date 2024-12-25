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

type ACKScanner struct {
	sourceIP   net.IP
	targetIP   net.IP
	sourcePort int
	portR      []int
	targetPort int
	ifi        *net.Interface
	options    gopacket.SerializeOptions
}

func NewACKScanner(targetIP net.IP, portArr []int) (*ACKScanner, error) {
	sourceIP, ifi, err := GetSource(targetIP)
	if err != nil {
		return nil, err
	}

	return &ACKScanner{
		sourceIP:   sourceIP,
		targetIP:   targetIP,
		sourcePort: 54321, // random source port
		portR:      portArr,
		ifi:        ifi,
		options: gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		},
	}, nil
}

func (s *ACKScanner) buildPacket() ([]byte, error) {
	eth := layers.Ethernet{
		SrcMAC:       s.ifi.HardwareAddr,
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := layers.IPv4{
		Version:  4,
		TTL:      64,
		IHL:      5,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    s.sourceIP,
		DstIP:    s.targetIP,
	}

	tcp := layers.TCP{
		SrcPort: layers.TCPPort(s.sourcePort),
		DstPort: layers.TCPPort(s.targetPort),
		Seq:     0,
		ACK:     true,
		Window:  14600,
	}

	tcp.SetNetworkLayerForChecksum(&ip4)

	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, s.options, &eth, &ip4, &tcp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *ACKScanner) Scan(port int) (string, error) {
	var report string

	packet, err := s.buildPacket()
	if err != nil {
		return report, fmt.Errorf("Error building ACK Packet: %v\n", err)
	}

	if err = s.sendPacket(packet); err != nil {
		return report, fmt.Errorf("Error sending ACK Packet: %v\n", err)
	}

	state, err := s.listen(time.Second * 5)
	return fmt.Sprintf("%s", state), err
}

func (s *ACKScanner) sendPacket(packet []byte) error {
	handle, err := pcap.OpenLive(s.ifi.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	return handle.WritePacketData(packet)
}

// TODO: Add the ackstate type and make open, closed, filtered etc... constants
func (s *ACKScanner) listen(timeout time.Duration) (ACKState, error) {
	handle, err := pcap.OpenLive(s.ifi.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return "", err
	}
	defer handle.Close()

	start := time.Now()

	for {
		if time.Since(start) > timeout {
			// return AckFiltered, fmt.Errorf("No response received till timeout\n") // no response gotten
			return AckFiltered, nil
		}

		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue // no packet is available yet
		} else if err != nil {
			return "", fmt.Errorf("Error reading packet: %v\n", err)
		}

		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			if tcp.SrcPort == layers.TCPPort(s.targetPort) && tcp.DstPort == layers.TCPPort(s.sourcePort) {
				if tcp.RST {
					return AckUnfiltered, nil
				}
			}
		}

		// check for ICMP unreachable responses to detect filtered ports by firewalls
		if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
			icmp, _ := icmpLayer.(*layers.ICMPv4)
			if icmp.TypeCode.Type() == layers.ICMPv4TypeDestinationUnreachable {
				return AckFiltered, nil
			}
		}
	}
}

func (s *ACKScanner) Start() error {
	fmt.Println("WARNING -> Use ACK Scanner for already found open|filtered ports (do not scan already known closed ports, you might get false results)")
	var wg sync.WaitGroup

	report := make(chan string)

	fmt.Println("Starting ... ")

	wg.Add(1)

	for i := 0; i < len(s.portR); i++ {
		log.Printf("Starting ACK scan (to check for firewalls) on %s:%d from %s\n", s.targetIP.String(), s.portR[i], s.sourceIP.String())
		go func(i int) {
			defer wg.Done()

			s.targetPort = s.portR[i]

			rStr, err := s.Scan(s.targetPort)
			if err != nil {
				log.Printf("Error in ACK scan on %s:%d -> %v\n", s.targetIP.String(), s.targetPort, err)
			}
			report <- fmt.Sprintf("Port %d: %s\n", s.targetPort, rStr)
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

func (s *ACKScanner) Stop() {
	log.Println("Stopping ACK scanner...")
	return
}
