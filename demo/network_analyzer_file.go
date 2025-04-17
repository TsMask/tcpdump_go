package demo

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var frameDataNumber int64 = 0 // 帧编号

// networkAnalyzerFile is a function that takes a packet and logs it to a file.
func networkAnalyzerFile(packet gopacket.Packet, capturedPackets int) {
	logFile, err := os.OpenFile("demo/network_analyzer_file.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Printf("Failed to create log file: %v\n", err)
		os.Exit(1)
	}
	defer logFile.Close()

	s := parseDataToMeta(packet)
	logFile.WriteString(fmt.Sprintf("%d %#v \n", capturedPackets, s))
}

// FrameMetaData 数据帧元信息
type FrameMetaData struct {
	Number      int    `json:"number"`
	Time        int64  `json:"time"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Length      int    `json:"length"`
	Info        string `json:"info"`
	Data        string `json:"data"` // 原始数据byte[] base64 编码数据
}

func parseDataToMeta(packet gopacket.Packet) FrameMetaData {
	// 使用原子操作获取当前帧号并自增
	currentFrameNumber := atomic.AddInt64(&frameDataNumber, 1)
	frameSrc := ""      // 源主机IP
	frameDst := ""      // 目的主机IP
	frameProtocol := "" // 协议
	frameInfo := ""     // 信息

	// for _, v := range packet.Layers() {
	// 	fmt.Println("====packet", v.LayerType().String())
	// }
	// fmt.Println("====packet ", len(packet.Layers()))

	// 网络层
	// fmt.Println(packet.NetworkLayer())
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		src, dst := networkLayer.NetworkFlow().Endpoints()
		frameSrc = src.String()
		frameDst = dst.String()
		if frameDst == "ff:ff:ff:ff" {
			frameDst = "Broadcast"
		}
	}

	// 传输层
	// fmt.Println(packet.TransportLayer())
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		frameProtocol = transportLayer.LayerType().String()
		switch layer := transportLayer.(type) {
		case *layers.TCP: // 传输控制协议，提供可靠的数据传输。
			var flagsDesc []string
			if layer.FIN {
				flagsDesc = append(flagsDesc, "FIN")
			}
			if layer.SYN {
				flagsDesc = append(flagsDesc, "SYN")
			}
			if layer.RST {
				flagsDesc = append(flagsDesc, "RST")
			}
			if layer.PSH {
				flagsDesc = append(flagsDesc, "PSH")
			}
			if layer.ACK {
				flagsDesc = append(flagsDesc, "ACK")
			}
			if layer.URG {
				flagsDesc = append(flagsDesc, "URG")
			}
			if layer.ECE {
				flagsDesc = append(flagsDesc, "ECE")
			}
			if layer.CWR {
				flagsDesc = append(flagsDesc, "CWR")
			}
			if layer.NS {
				flagsDesc = append(flagsDesc, "NS")
			}

			frameInfo = fmt.Sprintf("%v -> %v [%s], Seq=%d Ack=%d Win=%d Len=%d ", layer.SrcPort, layer.DstPort, strings.Join(flagsDesc, ", "), layer.Seq, layer.Ack, layer.Window, len(layer.Payload))
		case *layers.UDP: // 用户数据报协议，提供无连接的快速数据传输。
			frameInfo = fmt.Sprintf("%v -> %v Len=%d ", layer.SrcPort, layer.DstPort, len(layer.Payload))
		case *layers.UDPLite:
			frameInfo = fmt.Sprintf("%v -> %v Len=%d ", layer.SrcPort, layer.DstPort, len(layer.Payload))
		case *layers.SCTP: // 流控制传输协议，支持多流和多宿主机。
			frameInfo = fmt.Sprintf("%v -> %v Len=%d ", layer.SrcPort, layer.DstPort, len(layer.Payload))
		}
	}

	// 应用层协议判断
	switch {
	case packet.Layer(layers.LayerTypeARP) != nil:
		arp := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
		frameSrc = net.IP(arp.SourceProtAddress).String()
		frameDst = net.IP(arp.DstProtAddress).String()
		frameProtocol = "ARP"
		frameInfo = fmt.Sprintf("Who has %s? Tell %s", frameDst, frameSrc)
	case packet.Layer(layers.LayerTypeVRRP) != nil:
		frameProtocol = "VRRP"
		frameInfo = "Announcement (v2)"
	case packet.Layer(layers.LayerTypeIGMP) != nil:
		switch layer := packet.Layer(layers.LayerTypeIGMP).(type) {
		case *layers.IGMP:
			frameProtocol = fmt.Sprintf("IGMPv%d", layer.Version)
			frameInfo = fmt.Sprintf("%s %s", layer.Type.String(), layer.GroupAddress.String())
		case *layers.IGMPv1or2:
			frameProtocol = fmt.Sprintf("IGMPv%d", layer.Version)
			frameInfo = fmt.Sprintf("%s %s", layer.Type.String(), layer.GroupAddress.String())
		}
	case packet.Layer(layers.LayerTypeICMPv4) != nil:
		icmpv4 := packet.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		frameProtocol = "ICMP"
		frameInfo = icmpv4.TypeCode.String()
	case packet.Layer(layers.LayerTypeICMPv6) != nil:
		icmpv6 := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
		frameProtocol = "ICMPv6"
		frameInfo = icmpv6.TypeCode.String()
	case packet.Layer(layers.LayerTypeSTP) != nil:
		stp := packet.Layer(layers.LayerTypeSTP).(*layers.STP)
		rootIdentifier := stp.RouteID
		frameSrc = rootIdentifier.HwAddr.String()
		frameDst = stp.BridgeID.HwAddr.String()
		frameProtocol = "STP"
		frameInfo = fmt.Sprintf("MST. Root = %d/%d/%s  Cost = %d  Port = 0x%x", rootIdentifier.Priority, rootIdentifier.SysID, frameSrc, stp.Cost, stp.PortID)
	case packet.Layer(layers.LayerTypeSIP) != nil:
		sip := packet.Layer(layers.LayerTypeSIP).(*layers.SIP)
		frameProtocol = "SIP"
		if sip.IsResponse {
			frameInfo = fmt.Sprintf("%d %s", sip.ResponseCode, sip.ResponseStatus)
		} else {
			frameInfo = fmt.Sprintf("%s %s", sip.Method, sip.RequestURI)
		}
	case packet.Layer(layers.LayerTypeDNS) != nil:
		dns := packet.Layer(layers.LayerTypeDNS).(*layers.DNS)
		frameProtocol = "DNS"
		fmt.Printf("%+v \n", dns.Contents)
		msg := []string{}
		if len(dns.Questions) > 0 {
			for _, v := range dns.Questions {
				msg = append(msg, fmt.Sprintf("%s %s", v.Type, v.Name))
			}
		}
		if len(dns.Answers) > 0 {
			for _, v := range dns.Answers {
				msg = append(msg, fmt.Sprintf("%s %s", v.Type, v.Name))
			}
		}
		frameInfo = fmt.Sprintf("%s %s 0x%x %s", dns.ResponseCode.String(), dns.OpCode.String(), dns.ID, strings.Join(msg, " "))
	case packet.Layer(layers.LayerTypeDHCPv6) != nil:
		dhcpv6 := packet.Layer(layers.LayerTypeDHCPv6).(*layers.DHCPv6)
		frameProtocol = "DHCPv6"
		frameInfo = fmt.Sprintf("%s XID: 0x%+x", dhcpv6.MsgType.String(), dhcpv6.TransactionID)
	case packet.Layer(layers.LayerTypeTLS) != nil:
		tls := packet.Layer(layers.LayerTypeTLS).(*layers.TLS)
		if len(tls.AppData) > 0 {
			item := tls.AppData[0]
			frameProtocol = item.Version.String()
			frameInfo = item.ContentType.String()
		} else if len(tls.Handshake) > 0 {
			item := tls.Handshake[0]
			frameProtocol = item.ClientHello.ProtocolVersion.String()
			frameInfo = "Client Hello"
		} else {
			frameProtocol = "TLS"
			frameInfo = "Unknown"
		}
	}

	// 数据
	frameMeta := FrameMetaData{
		Number:      int(currentFrameNumber),
		Time:        packet.Metadata().Timestamp.UnixMicro(),
		Source:      frameSrc,
		Destination: frameDst,
		Protocol:    frameProtocol,
		Length:      packet.Metadata().Length,
		Info:        frameInfo,
		Data:        "base64.StdEncoding.EncodeToString(packet.Data())",
	}

	if frameMeta.Protocol == "" {
		fmt.Printf("%+v \n", frameMeta)
	}

	return frameMeta
}
