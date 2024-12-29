package portslibK

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (s *SynScanner) BuildSYNPacket(srcPort uint16, ifi *net.Interface, destMac net.HardwareAddr) ([]byte, error) {
	ipLayer, tcpLayer, ethLayer := s.BuildLayers(srcPort, ifi, destMac)

	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &ipLayer, &tcpLayer, &ethLayer); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (s *SynScanner) BuildLayers(srcPort uint16, ifi *net.Interface, destMac net.HardwareAddr) (layers.IPv4, layers.TCP, layers.Ethernet) {
	ipLayer := layers.IPv4{
		SrcIP:    s.sourceIP,
		DstIP:    s.targetIP,
		Version:  4,
		TTL:      255, // optional I guess
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(s.port),
		SYN:     true,
		// Window:  14600,
	}

	ethLayer := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		DstMAC:       destMac,
		SrcMAC:       ifi.HardwareAddr,
	}

	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

	return ipLayer, tcpLayer, ethLayer
}
