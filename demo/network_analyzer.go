package demo

import (
	"fmt"
	"os"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// networkAnalyzer is a function that takes a packet and logs it to a file.
func networkAnalyzer(packet gopacket.Packet, capturedPackets int) {
	logFile, err := os.OpenFile("demo/network_analyzer.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to create log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	s := parsePacket(packet)
	logFile.WriteString(fmt.Sprintf("%d %#v \n", capturedPackets, s))
}

type packetModel struct {
	TimeStp    time.Time
	SrcMAC     string
	DstMAC     string
	SrcIP      string
	DestIP     string
	SrcPort    uint16
	DstPort    uint16
	Protocol   string
	Length     int
	Payload    []byte
	PayloadStr string
}

func parsePacket(packet gopacket.Packet) packetModel {
	parsed := packetModel{
		TimeStp: packet.Metadata().Timestamp,
		Length:  packet.Metadata().Length,
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
