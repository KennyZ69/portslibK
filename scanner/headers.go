package scanner

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func BuildSYNPacket(srcIP, destIP net.IP, srcPort, destPort uint16) ([]byte, error) {
	ipLayer := layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    destIP,
		Version:  4,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(destPort),
		SYN:     true,
		Window:  14600,
	}

	ethLayer := layers.Ethernet{
		EthernetType: layers.EthernetTypeIPv4,
		// Get and add the source and destination mac addr
	}

	tcpLayer.SetNetworkLayerForChecksum(&ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	if err := gopacket.SerializeLayers(buf, opts, &ipLayer, &tcpLayer); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
