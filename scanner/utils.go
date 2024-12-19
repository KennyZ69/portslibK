package scanner

import (
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
)

func GetSource(target net.IP) (net.IP, *net.Interface, error) {
	// conn, err := net.Dial("udp", fmt.Sprintf("%s:80", target.String()))
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("Error getting source IP: %v\n", err)
	// }
	// defer conn.Close()
	//
	// localAddr := conn.LocalAddr().(*net.UDPAddr)
	// ifi, err := net.InterfaceByName(localAddr.Network())
	// if err != nil {
	// 	return nil, nil, fmt.Errorf("Error couldn't get the net interface: %v\n", err)
	// }
	// return localAddr.IP, ifi, nil

	router, err := routing.New()
	if err != nil {
		return nil, nil, fmt.Errorf("Error creating a new router: %v\n", err)
	}
	ifi, _, srcIP, err := router.Route(target)
	if err != nil {
		return nil, nil, fmt.Errorf("Error routing the target IP: %v\n", err)
	}
	return srcIP, ifi, nil
}

func checksum(data []byte) uint16 {
	var sum uint32

	// converting, shifting the bits and the "|" is a bitwise OR to combine those two 8-bit values into one 16 bit val
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// ensuring no overflown bits remain there, extracting them and adding them to the lower 16 bits
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)

	// one's complement -> inverts all bits so 0 to 1 and 1 to 0
	return uint16(^sum)
	// return uint16(^sum)
}

func (s *SynScanner) GetMac() (net.HardwareAddr, error) {
	var destARP net.IP

	// if getaway != nil {
	// 	destARP = getaway
	// } else {
	// 	destARP = dstIP
	// }

	destARP = s.targetIP

	handle, err := pcap.OpenLive(s.ifi.Name, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	start := time.Now()

	eth := layers.Ethernet{
		SrcMAC:       s.ifi.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(s.ifi.HardwareAddr),
		SourceProtAddress: []byte(s.sourceIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(destARP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()

	// send single arp request
	if err := gopacket.SerializeLayers(buf, s.options, &eth, &arp); err != nil {
		return nil, err
	}

	if err = handle.WritePacketData(buf.Bytes()); err != nil {
		return nil, err
	}

	// wait for an arp reply for a done time
	for {
		if time.Since(start) > time.Second*3 {
			return nil, fmt.Errorf("Timeout reached getting ARP reply\n")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}

		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := p.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if net.IP(arp.SourceProtAddress).Equal(destARP) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}

	}
}
