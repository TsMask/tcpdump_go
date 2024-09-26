package demo

import (
	"encoding/binary"
	"fmt"
	"strings"

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
	prefixStr := string(data[:12])
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
