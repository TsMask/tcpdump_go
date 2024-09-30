package demo

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// networkDSCPAndECN 提取 TOS 字段并获取 DSCP 和 ECN
func networkDSCPAndECN(tos uint8) (string, string) {
	// 提取 DSCP 和 ECN
	dscp := tos >> 2  // 高 6 位
	ecn := tos & 0x03 // 低 2 位

	// 定义 DSCP 映射
	dscpMapping := map[uint8]string{
		0:  "Default CS0", // Default Forwarding (DF)
		8:  "CS1",         // Class Selector 1
		16: "CS2",         // Class Selector 2
		24: "CS3",         // Class Selector 3
		32: "CS4",         // Class Selector 4
		40: "CS5",         // Class Selector 5
		48: "CS6",         // Class Selector 6
		56: "CS7",         // Class Selector 7
	}

	// 定义 ECN 映射
	ecnMapping := map[uint8]string{
		0: "Not-ECT", // Not ECN-Capable Transport
		1: "ECT(1)",  // ECN-Capable Transport
		2: "ECT(0)",  // ECN-Capable Transport
		3: "CE",      // Congestion Experienced
	}

	// 返回可读的 DSCP 和 ECN 字符串
	return dscpMapping[dscp], ecnMapping[ecn]
}

// networkFlagsDesc 生成标志描述
func networkFlagsDesc(flags layers.IPv4Flag) string {
	f := fmt.Sprintf("Flags: 0x%X", flags)
	if flags&layers.IPv4DontFragment != 0 {
		f += ", Don't fragment"
	}
	if flags&layers.IPv4MoreFragments != 0 {
		f += ", More fragments"
	}
	return f
}

// networkFlagsEvil 生成标志描述 Evil
func networkFlagsEvil(flags layers.IPv4Flag) (int, string) {
	if flags&layers.IPv4EvilBit != 0 {
		return 1, "Set"
	}
	return 0, "Not set"
}

// networkFlagsDF 生成标志描述 DF
func networkFlagsDF(flags layers.IPv4Flag) (int, string) {
	if flags&layers.IPv4DontFragment != 0 {
		return 1, " Set"
	}
	return 0, "Not set"
}

// networkFlagsMF 生成标志描述 MF
func networkFlagsMF(flags layers.IPv4Flag) (int, string) {
	if flags&layers.IPv4MoreFragments != 0 {
		return 1, " Set"
	}
	return 0, "Not set"
}

// networkOffset 二进制Fragment Offset表示 ...0 0000 0000 0000
func networkOffset(offset uint16) string {
	return fmt.Sprintf("...0 %04b %04b %04b %04b",
		(offset>>12)&0xF, // 高四位
		(offset>>8)&0xF,  // 次四位
		(offset>>4)&0xF,  // 再次四位
		offset&0xF,       // 低四位
	)
}

// transportFlagsDesc 生成标志描述
func transportFlagsDesc(layer *layers.TCP) (byte, string) {
	var flags byte
	var flagsDesc []string
	if layer.FIN {
		flags |= 1 << 0 // 0b00000001
		flagsDesc = append(flagsDesc, "FIN")
	}
	if layer.SYN {
		flags |= 1 << 1 // 0b00000010
		flagsDesc = append(flagsDesc, "SYN")
	}
	if layer.RST {
		flags |= 1 << 2 // 0b00000100
		flagsDesc = append(flagsDesc, "RST")
	}
	if layer.PSH {
		flags |= 1 << 3 // 0b00001000
		flagsDesc = append(flagsDesc, "PSH")
	}
	if layer.ACK {
		flags |= 1 << 4 // 0b00010000
		flagsDesc = append(flagsDesc, "ACK")
	}
	if layer.URG {
		flags |= 1 << 5 // 0b00100000
		flagsDesc = append(flagsDesc, "URG")
	}
	if layer.ECE {
		flags |= 1 << 6 // 0b01000000
		flagsDesc = append(flagsDesc, "ECE")
	}
	if layer.CWR {
		flags |= 1 << 7 // 0b10000000
		flagsDesc = append(flagsDesc, "CWR")
	}
	if layer.NS {
		flagsDesc = append(flagsDesc, "NS")
	}

	return flags, strings.Join(flagsDesc, ", ")
}

// transportFlagsStatus 生成标志描述状态
func transportFlagsStatus(flag bool) (int, string) {
	if flag {
		return 1, " Set"
	}
	return 0, "Not set"
}

// bytesToHexString 转换为十六进制字符串格式
func bytesToHexString(data []byte) string {
	var sb strings.Builder
	for i, b := range data {
		if i > 0 {
			sb.WriteString(":")
		}
		sb.WriteString(fmt.Sprintf("%02x", b))
	}
	return sb.String()
}

// transportOptions 生成头部选项描述
func transportOptions(options []layers.TCPOption) (uint8, string) {
	var opts []string
	var optLen uint8
	for _, opt := range options {
		if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) == 2 {
			optLen += opt.OptionLength
			opts = append(opts, fmt.Sprintf("%s val %v",
				opt.OptionType.String(),
				binary.BigEndian.Uint16(opt.OptionData),
			))
		} else if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) == 8 {
			optLen += opt.OptionLength
			opts = append(opts, fmt.Sprintf("%s val %v echo %v",
				opt.OptionType.String(),
				binary.BigEndian.Uint32(opt.OptionData[:4]),
				binary.BigEndian.Uint32(opt.OptionData[4:8]),
			))
		} else {
			optLen += opt.OptionLength
			opts = append(opts, opt.OptionType.String())
		}
	}
	return optLen, strings.Join(opts, ", ")
}

// applicationHTTP 辨别 HTTP 数据
func applicationHTTP(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	prefixStr := string(data)
	return strings.HasPrefix(prefixStr, "GET ") || strings.HasPrefix(prefixStr, "POST ") ||
		strings.HasPrefix(prefixStr, "PUT ") || strings.HasPrefix(prefixStr, "DELETE ") ||
		strings.HasPrefix(prefixStr, "HEAD ") || strings.HasPrefix(prefixStr, "OPTIONS ") ||
		strings.HasPrefix(prefixStr, "HTTP/")
}

// applicationHTTP 处理 HTTP 请求
func applicationHTTPProcess(data string) map[string]map[string]any {
	p := make(map[string]map[string]any, 0)
	// 按行分割
	lines := strings.Split(data, "\r\n")
	for i, line := range lines {
		if i == 0 {
			label := line + "\r\n"
			p[label] = map[string]any{
				"label":  label,
				"length": len([]byte(label)),
				"key":    "",
				"value":  "",
			}
			continue
		}

		// 空行表示头部结束，Body开始
		if line == "" {
			break
		}

		label := line + "\r\n"
		p[label] = map[string]any{
			"label":  label,
			"length": len([]byte(label)),
			"key":    "",
			"value":  "",
		}

		// 分割键值对
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			p[label]["key"] = key
			p[label]["value"] = value
		}
	}
	return p
}

// colorRuleFB 着色规则-F前景,B背景
//
// This file was created by Wireshark. Edit with care.
func colorRuleFB(packet gopacket.Packet) (int, int) {
	// Ethernet
	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		eth := ethernetLayer.(*layers.Ethernet)
		ethData := eth.Contents
		// Broadcast 检查第一个字节的最低位
		// #babdb6, #ffffff
		if len(ethData) > 0 && (ethData[0]&1) == 1 {
			return 12238262, 16777215
		}
		// Routing CDP (Cisco Discovery Protocol) 检查前三个字节
		// #12272e, #fff3d6
		if ethernetLayer.LayerPayload()[0] == 0x01 && ethernetLayer.LayerPayload()[1] == 0x00 && ethernetLayer.LayerPayload()[2] == 0x0c {
			return 1189678, 16774102
		}
		// Routing CARP (Common Address Redundancy Protocol) uses a specific Ethernet type (0x0800)
		// #12272e, #fff3d6
		if ethernetLayer.LayerType() == 0x0800 {
			return 1189678, 16774102
		}
	}
	// ARP
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		// #12272e, #faf0d7
		return 1189678, 16445655
	}
	// ICMP
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		// #12272e, #fce0ff
		return 1189678, 16572671
	}
	if icmpLayer := packet.Layer(layers.LayerTypeICMPv6); icmpLayer != nil {
		// #12272e, #fce0ff
		return 1189678, 16572671
	}
	// SCTP
	if sctpLayer := packet.Layer(layers.LayerTypeSCTP); sctpLayer != nil {
		sctp := sctpLayer.(*layers.SCTP)
		// SCTP ABORT
		// #fffc9c, #a40000
		if sctp.Checksum == 6 {
			return 16776348, 10747904
		}
	}
	// TCP
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		// TCP SYN/FIN
		// #12272e, #a0a0a0
		if tcp.SYN && tcp.FIN {
			return 1189678, 10526880
		}
		// TCP RST
		// #fffc9c, #a40000
		if tcp.RST {
			return 16776348, 10747904
		}
		// HTTP
		// #12272e, #e4ffc7
		if tcp.SrcPort == 80 || tcp.DstPort == 80 || tcp.SrcPort == 443 || tcp.DstPort == 443 {
			return 1189678, 15007687
		}
		// 检查 SMB - 通常基于 TCP 445 或 139
		// #12272e, #feffd0
		if tcp.SrcPort == 445 || tcp.DstPort == 445 || tcp.SrcPort == 139 || tcp.DstPort == 139 {
			return 1189678, 16711632
		}
		// Routing BGP usually runs on TCP port 179
		// #12272e, #fff3d6
		if tcp.DstPort == 179 || tcp.SrcPort == 179 {
			return 1189678, 16774102
		}
	}
	// UDP
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		// 检查 SMB NetBIOS 名称服务 (NBNS) - 端口 53
		// 检查 SMB NetBIOS 数据报服务 (NBDS) - 端口 138
		if udp.SrcPort == 53 || udp.DstPort == 53 || udp.SrcPort == 138 || udp.DstPort == 138 {
			return 1189678, 16711632
		}
	}
	// IPv4
	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ipv4 := ipv4Layer.(*layers.IPv4)
		// TCP(6)
		// #12272e, #e7e6ff
		if ipv4.Protocol == layers.IPProtocolTCP {
			return 1189678, 15197951
		}
		// UDP(17)
		// #12272e, #daeeff
		if ipv4.Protocol == layers.IPProtocolUDP || ipv4.Protocol == layers.IPProtocolUDPLite {
			return 1189678, 14348031
		}
		// Routing EIGRP(0x2f) OSPF(89)
		// #12272e, #fff3d6
		if ipv4.Protocol == 0x2f || ipv4.Protocol == layers.IPProtocolOSPF {
			return 1189678, 16774102
		}
		// Routing
		// GVRP (GARP VLAN Registration Protocol)
		// GVRP typically utilizes the same multicast address as GARP
		// HSRP (Hot Standby Router Protocol) uses multicast IP 224.0.0.2
		// VRRP (Virtual Router Redundancy Protocol) uses multicast IP 224.0.0.18
		// #12272e, #fff3d6
		if ipv4.DstIP.Equal(net.IPv4(224, 0, 0, 2)) || ipv4.DstIP.Equal(net.IPv4(224, 0, 0, 100)) {
			return 1189678, 16774102
		}
	}
	return 16222087, 1189678 // 默认颜色值 #f78787, #12272e
}
