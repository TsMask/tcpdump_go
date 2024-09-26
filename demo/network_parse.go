package demo

import (
	"fmt"
	"log"
	"os"
	"tcpdump_go/demo/util"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// networkParse
func networkParse(packet gopacket.Packet) {
	if packet == nil {
		fmt.Fprint(os.Stdout, "nil packet \n")
		return
	}

	if err := packet.ErrorLayer(); err != nil {
		fmt.Fprintf(os.Stdout, "skipping packet %v: %v\n", packet, err)
		return
	}

	parsePacketFrame(packet)
	// parsePacketT(packet)
	// parsePacketTT(packet)
}

func parsePacketF(packet gopacket.Packet) {
	logFile, err := os.OpenFile("demo/network_parse.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to create log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	log.SetOutput(logFile)
	log.Println(" ##### start")
	for _, v := range packet.Layers() {
		log.Println(v.LayerType(), len(v.LayerPayload()))
	}
	// log.Println("Data", len(packet.Data()))
	// log.Println("Dump", len(packet.Dump()))
	// log.Println(packet.Dump())
	log.Println("  ---  ")

	// 连接层
	// fmt.Println(packet.LinkLayer())
	if ethernetLayer := packet.LinkLayer(); ethernetLayer != nil {
		log.Println("\n=> LinkLayer", ethernetLayer.LayerType())
		src, dst := ethernetLayer.LinkFlow().Endpoints()
		// dstHost := dst.String()
		// if dstHost == "ff:ff:ff:ff:ff:ff" {
		// 	dstHost = "Broadcast"
		// }
		log.Println(ethernetLayer.LinkFlow().EndpointType(), src.String(), dst.String())
		log.Println(ethernetLayer.LinkFlow().String())

		length := len(ethernetLayer.LayerContents()) + len(ethernetLayer.LayerPayload())
		log.Println(len(ethernetLayer.LayerContents()), "+", len(ethernetLayer.LayerPayload()), "=", length)

		// ASCII:
		// log.Printf("\nASCII\n%s\n", ethernetLayer.LayerContents())
		// HexDump:
		log.Printf("\nHexDump\n%s\n", util.HexDump(ethernetLayer.LayerContents(), "|", "|"))
	}

	// 网络层
	// fmt.Println(packet.NetworkLayer())
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		log.Println("\n=> NetworkLayer", networkLayer.LayerType())
		src, dst := networkLayer.NetworkFlow().Endpoints()
		// dstHost := dst.String()
		// if dstHost == "ff:ff:ff:ff" {
		// 	dstHost = "Broadcast"
		// }
		log.Println(networkLayer.NetworkFlow().EndpointType(), src.String(), dst.String())
		log.Println(networkLayer.NetworkFlow().String())

		length := len(networkLayer.LayerContents()) + len(networkLayer.LayerPayload())
		log.Println(len(networkLayer.LayerContents()), "+", len(networkLayer.LayerPayload()), "=", length)

		switch layer := networkLayer.(type) {
		case *layers.IPv4:
			log.Printf("-> (tos 0x%x, ttl %d, id %d, offset %d, flags [%s], proto %s (%d), length %d)\n", layer.TOS, layer.TTL, layer.Id, layer.FragOffset, layer.Flags, layer.Protocol, layer.Protocol, len(layer.Contents)+len(layer.Payload))

			log.Println("Version:", layer.Version)
			log.Println("TTL:", layer.TTL)
			log.Println("Id:", layer.Id)
			log.Println("FragOffset:", layer.FragOffset)
			log.Println("Flags:", layer.Flags)
			log.Println("Protocol:", layer.Protocol)
			baseLayer := layer.BaseLayer
			log.Println("BaseLayer Len:", len(baseLayer.LayerContents())+len(baseLayer.LayerPayload()))
			log.Println("Contents:", len(layer.Contents))
			log.Println("DstIP:", layer.DstIP)
			log.Println("SrcIP:", layer.SrcIP)
			log.Println("IHL:", layer.IHL)
			log.Println("Length:", layer.Length)
			log.Println("Padding:", layer.Padding)
			log.Println("Payload:", len(layer.Payload))
			log.Println("Options:", layer.Options)
			log.Println("TOS:", layer.TOS)
			if e, s := layer.VerifyChecksum(); e == nil {
				log.Println(e, s.Actual, s.Correct, s.Valid)
			}
		case *layers.IPv6:
			log.Printf("-> (flowlabel 0x%x, hlim %d, next-header %s (%d), payload length: %d)\n", layer.FlowLabel, layer.HopLimit, layer.NextHeader, layer.NextHeader, len(layer.Payload))

			log.Println("Version:", layer.Version)
			log.Println("FlowLabel:", layer.FlowLabel)
			log.Println("NextHeader:", layer.NextHeader.LayerType(), layer.NextHeader.String())
			log.Println("HopLimit:", layer.HopLimit)
			baseLayer := layer.BaseLayer
			log.Println("BaseLayer Len:", len(baseLayer.LayerContents())+len(baseLayer.LayerPayload()))
			log.Println("Contents:", len(layer.Contents))
			log.Println("DstIP:", layer.DstIP)
			log.Println("SrcIP:", layer.SrcIP)
			log.Println("Length:", layer.Length)
			log.Println("Payload:", len(layer.Payload))
			log.Println("HopByHop:", layer.HopByHop)
			log.Println("TrafficClass:", layer.TrafficClass)
		}

		// ASCII:
		// log.Printf("\nASCII\n%s\n", networkLayer.LayerContents())
		// HexDump:
		log.Printf("\nHexDump\n%s\n", util.HexDump(networkLayer.LayerContents(), "|", "|"))
	}

	// 传输层
	// fmt.Println(packet.TransportLayer())
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		log.Println("\n=> TransportLayer", transportLayer.LayerType())
		src, dst := transportLayer.TransportFlow().Endpoints()
		log.Println(transportLayer.TransportFlow().EndpointType(), src.String(), dst.String())
		log.Println(transportLayer.TransportFlow().String())

		length := len(transportLayer.LayerContents()) + len(transportLayer.LayerPayload())
		log.Println(len(transportLayer.LayerContents()), "+", len(transportLayer.LayerPayload()), "=", length)

		switch layer := transportLayer.(type) {
		case *layers.TCP:
			filgs, opt := util.TcpData(layer)
			log.Printf("-> TCP, Flags [%s], cksum 0x%x, seq %d, ack %d, win %d, options [%s], length %d",
				filgs, layer.Checksum, layer.Seq, layer.Ack, layer.Window, opt, length)
		case *layers.UDP:
			log.Printf("-> UDP, length %d", length)
		case *layers.UDPLite:
			log.Printf("-> UDPLite, length %d", length)
		default:
			log.Printf("-> %s, length %d", layer.LayerType(), length)
		}

		// ASCII:
		// log.Printf("\nASCII\n%s\n", transportLayer.LayerContents())
		// HexDump:
		log.Printf("\nHexDump\n%s\n", util.HexDump(transportLayer.LayerContents(), "|", "|"))
	}

	// 应用层
	// fmt.Println(packet.ApplicationLayer())
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		log.Println("\n=> ApplicationLayer", applicationLayer.LayerType())

		length := len(applicationLayer.LayerContents()) + len(applicationLayer.LayerPayload())
		log.Println(len(applicationLayer.LayerContents()), "+", len(applicationLayer.LayerPayload()), "=", length)

		switch layer := applicationLayer.(type) {
		case *layers.DNS:
			log.Printf("-> DNS,  %s", util.DnsData(layer))
		case *layers.SIP:
			log.Printf("-> SIP,  %s", util.SipData(layer))
		default:
			log.Printf("-> %s, length %d", layer.LayerType(), length)
		}

		// ASCII:
		// log.Printf("\nASCII\n%s\n", applicationLayer.LayerContents())
		// HexDump:
		log.Printf("\nHexDump\n%s\n", util.HexDump(applicationLayer.LayerContents(), "|", "|"))
	}

	log.Printf("=> Data %d\n", packet.Metadata().Length)
	// Data:
	// log.Printf("\nData\n%s\n", util.FormatPacketData(packet.Data()[14:]))
	// DataWithHeader:
	// log.Printf("\nDataWithHeader\n%s\n", util.FormatPacketData(packet.Data()))
	// HexDump:
	log.Printf("\nHexDump\n%s\n", util.HexDump(packet.Data(), "|", "|"))

	log.Println(" ##### end \n\n ")
}

func parsePacketT(packet gopacket.Packet) {
	fmt.Println("\n ===== \n ")

	// dumpStr := format.HexDump(packet.Data(), format.Options{LeftAsciiDelimiter: "|", RightAsciiDelimiter: "|"})
	// fmt.Println(dumpStr)

	fmt.Println(packet.String())
	fmt.Println(packet.Dump())
	fmt.Println(" ===== \n ")
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

func parsePacketTT(packet gopacket.Packet) {
	logFile, err := os.OpenFile("demo/network_parse.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to create log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	// Parse the packet
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
		// parsed.Payload = applicationLayer.Payload()
		parsed.PayloadStr = string(applicationLayer.Payload())
	}

	logFile.WriteString(fmt.Sprintf("%#v \n", parsed))
}
