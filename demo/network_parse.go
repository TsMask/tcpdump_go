package demo

import (
	"fmt"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// networkParse
func networkParse(packet gopacket.Packet) {
	logFile, err := os.OpenFile("demo/network_parse.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to create log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	s := parsePacketT(packet)
	logFile.WriteString(fmt.Sprintf("  %#v \n", s))
}

type packetModel2 struct {
	TimeStp    time.Time
	SrcMAC     string
	DstMAC     string
	SrcIP      string
	DestIP     string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	Length     int
	Dump       string
	Data       []byte
	Payload    []byte
	PayloadStr string
}

func parsePacketT(packet gopacket.Packet) packetModel2 {
	parsed := packetModel2{
		TimeStp: packet.Metadata().Timestamp,
		Length:  packet.Metadata().Length,
		Dump:    packet.Dump(),
		Data:    packet.Data(),
	}

	// Ethernet Layer
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		ethernet, _ := ethernetLayer.(*layers.Ethernet)
		parsed.SrcMAC = ethernet.SrcMAC.String()
		parsed.DstMAC = ethernet.DstMAC.String()
	}

	// IP Layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		parsed.SrcIP = ip.SrcIP.String()
		parsed.DestIP = ip.DstIP.String()
	}

	// TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		parsed.SrcPort = uint16(tcp.SrcPort)
		parsed.DstPort = uint16(tcp.DstPort)
		parsed.Protocol = "TCP"
	}

	// UDP layer
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		parsed.SrcPort = uint16(udp.SrcPort)
		parsed.DstPort = uint16(udp.DstPort)
		parsed.Protocol = "UDP"
	}

	// Application layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		parsed.Payload = applicationLayer.Payload()
		parsed.PayloadStr = string(applicationLayer.Payload())
	}

	return parsed
}
