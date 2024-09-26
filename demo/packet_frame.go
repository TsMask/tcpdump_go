package demo

import (
	"fmt"
	"log"
	"os"
	"tcpdump_go/demo/util"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type Tree struct {
	Label         string `json:"label,omitempty"`  // 显示的文本
	Filter        string `json:"filter,omitempty"` // 过滤条件
	Tree          []Tree `json:"tree,omitempty"`   // 子节点
	Start         int    `json:"start,omitempty"`  // 开始位置
	Length        int    `json:"length,omitempty"` // 长度
	DataSourceIdx int    `json:"data_source_idx,omitempty"`
	Severity      string `json:"severity,omitempty"`
	Type          string `json:"type,omitempty"`
	Fnum          int    `json:"fnum,omitempty"`
	URL           string `json:"url,omitempty"`
}

func parsePacketFrame(packet gopacket.Packet) {
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

		linkTree := linkLayerTree(ethernetLayer)
		log.Printf("Tree-> \n%#v\n", linkTree)
	}

	// 网络层
	// fmt.Println(packet.NetworkLayer())
	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		log.Println("\n=> NetworkLayer", networkLayer.LayerType())

		networkTree := networkLayerTree(networkLayer)
		log.Printf("Tree-> \n%#v\n", networkTree)
	}

	// 传输层
	// fmt.Println(packet.TransportLayer())
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		log.Println("\n=> TransportLayer", transportLayer.LayerType())

		transportTree := transportLayerTree(transportLayer)
		log.Printf("Tree-> \n%#v\n", transportTree)
	}

	// 应用层
	// fmt.Println(packet.ApplicationLayer())
	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		log.Println("\n=> ApplicationLayer", applicationLayer.LayerType())

		applicationTree := applicationLayerTree(applicationLayer)
		log.Printf("Tree-> \n%#v\n", applicationTree)
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

// linkLayerTree 连接层
func linkLayerTree(ethernetLayer gopacket.LinkLayer) Tree {
	src, dst := ethernetLayer.LinkFlow().Endpoints()
	return Tree{
		Label:         fmt.Sprintf("%s II, Src: %s, Dst: %s", ethernetLayer.LayerType(), src.String(), dst.String()),
		Filter:        "eth",
		Start:         0,
		Length:        len(ethernetLayer.LayerContents()),
		DataSourceIdx: 0,
		Tree: []Tree{
			{
				Label:         fmt.Sprintf("Destination: %s", dst.String()),
				Filter:        fmt.Sprintf("eth.dst == %s", dst.String()),
				Start:         0,
				Length:        len(dst.Raw()),
				DataSourceIdx: 0,
				Tree: []Tree{
					{
						Label:         fmt.Sprintf("Address: %s", dst.String()),
						Filter:        fmt.Sprintf("eth.addr == %s", dst.String()),
						Start:         0,
						Length:        6,
						DataSourceIdx: 0,
						Tree:          []Tree{},
						Severity:      "",
						Type:          "",
						Fnum:          926233912,
						URL:           "",
					},
					{
						Label:         ".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)",
						Filter:        "eth.dst.lg == 0",
						Start:         0,
						Length:        3,
						DataSourceIdx: 0,
						Tree:          []Tree{},
						Severity:      "",
						Type:          "",
						Fnum:          926233912,
						URL:           "",
					},
					{
						Label:         ".... ...0 .... .... .... .... = IG bit: Individual address (unicast)",
						Filter:        "eth.dst.ig == 0",
						Start:         0,
						Length:        3,
						DataSourceIdx: 0,
						Tree:          []Tree{},
						Severity:      "",
						Type:          "",
						Fnum:          926233912,
						URL:           "",
					},
				},
				Severity: "",
				Type:     "",
				Fnum:     0,
				URL:      "",
			},
			{
				Label:         fmt.Sprintf("Source: %s", src.String()),
				Filter:        fmt.Sprintf("eth.src == %s", src.String()),
				Start:         len(dst.Raw()),
				Length:        len(src.Raw()),
				DataSourceIdx: 0,
				Tree: []Tree{
					{
						Label:         fmt.Sprintf("Address: %s", src.String()),
						Filter:        fmt.Sprintf("eth.addr == %s", src.String()),
						Start:         len(dst.Raw()),
						Length:        len(src.Raw()),
						DataSourceIdx: 0,
						Tree:          []Tree{},
						Severity:      "",
						Type:          "",
						Fnum:          926233912,
						URL:           "",
					},
					{
						Label:         ".... ..0. .... .... .... .... = LG bit: Globally unique address (factory default)",
						Filter:        "eth.src.lg == 0",
						Start:         len(src.Raw()),
						Length:        len(src.Raw()) / 2,
						DataSourceIdx: 0,
						Tree:          []Tree{},
						Severity:      "",
						Type:          "",
						Fnum:          926233912,
						URL:           "",
					},
					{
						Label:         ".... ...0 .... .... .... .... = IG bit: Individual address (unicast)",
						Filter:        "eth.src.ig == 0",
						Start:         len(src.Raw()),
						Length:        len(src.Raw()) / 2,
						DataSourceIdx: 0,
						Tree:          []Tree{},
						Severity:      "",
						Type:          "",
						Fnum:          926233912,
						URL:           "",
					},
				},
				Severity: "",
				Type:     "",
				Fnum:     0,
				URL:      "",
			},
			{
				Label:         "Type: IPv4 (0x0800)",
				Filter:        "eth.type == 0x0800",
				Start:         len(dst.Raw()) + len(src.Raw()),
				Length:        len(ethernetLayer.LayerContents()) - (len(dst.Raw()) + len(src.Raw())),
				DataSourceIdx: 0,
				Tree:          []Tree{},
				Severity:      "",
				Type:          "",
				Fnum:          0,
				URL:           "",
			},
		},
		Severity: "",
		Type:     "proto",
		Fnum:     1052,
		URL:      "",
	}
}

// networkLayerTree 网络层
func networkLayerTree(networkLayer gopacket.NetworkLayer) Tree {
	var tree Tree
	switch layer := networkLayer.(type) {
	case *layers.IPv4:
		// 偏移量取连接层的长度Length
		linkLayerLen := 14
		networkLayerLen := len(layer.Contents)

		version := layer.Version
		length := layer.Length
		srcIP := layer.SrcIP
		dstIP := layer.DstIP
		ihl := layer.IHL
		headerLength := ihl * 4 // 提取头部长度
		tos := layer.TOS
		dscp, ecn := networkDSCPAndECN(tos)
		identification := layer.Id
		flags := layer.Flags // 提取标志位
		// 生成标志描述
		flagsDesc := networkFlagsDesc(flags)
		rb, rbDesc := networkFlagsEvil(flags)
		df, dfDesc := networkFlagsDF(flags)
		mf, mfDesc := networkFlagsMF(flags)
		fragOffset := layer.FragOffset
		fragOffsetDesc := networkOffset(fragOffset)
		ttl := layer.TTL
		proto := layer.Protocol
		checksum := layer.Checksum

		tree = Tree{
			Label:         fmt.Sprintf("Internet Protocol Version %d, Src: %s, Dst: %s", version, srcIP, dstIP),
			Filter:        "ip",
			Start:         linkLayerLen,
			Length:        networkLayerLen,
			DataSourceIdx: 0,
			Tree: []Tree{
				{
					Label:         fmt.Sprintf("%04b .... = Version: %d", version, version),
					Filter:        fmt.Sprintf("ip.version == %d", version),
					Start:         linkLayerLen,
					Length:        1,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf(".... 0101 = Header Length: %d bytes (%d)", headerLength, ihl),
					Filter:        fmt.Sprintf("ip.hdr_len == %d", headerLength),
					Start:         linkLayerLen,
					Length:        1,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Differentiated Services Field: 0x%02x (DSCP: %s, ECN: %s)", tos, dscp, ecn),
					Filter:        fmt.Sprintf("ip.dsfield == 0x%02x", tos),
					Start:         linkLayerLen + 1,
					Length:        1,
					DataSourceIdx: 0,
					Tree: []Tree{
						{
							Label:         fmt.Sprintf("0000 00.. = Differentiated Services Codepoint: %s (%d)", dscp, tos),
							Filter:        fmt.Sprintf("ip.dsfield.dscp == %d", tos>>2),
							Start:         linkLayerLen + 1,
							Length:        1,
							DataSourceIdx: 0,
							Tree:          []Tree{},
							Severity:      "",
							Type:          "",
							Fnum:          926233912,
							URL:           "",
						},
						{
							Label:         fmt.Sprintf(".... ..00 = Explicit Congestion Notification: %s Capable Transport (%d)", ecn, tos),
							Filter:        fmt.Sprintf("ip.dsfield.ecn == %d", tos&0x03),
							Start:         linkLayerLen + 1,
							Length:        1,
							DataSourceIdx: 0,
							Tree:          []Tree{},
							Severity:      "",
							Type:          "",
							Fnum:          926233912,
							URL:           "",
						},
					},
					Severity: "",
					Type:     "",
					Fnum:     0,
					URL:      "",
				},
				{
					Label:         fmt.Sprintf("Total Length: %d", length),
					Filter:        fmt.Sprintf("ip.len ==  %d", length),
					Start:         linkLayerLen + 2,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Identification: 0x%X (%d)", identification, identification),
					Filter:        fmt.Sprintf("ip.id == 0x%X", identification),
					Start:         linkLayerLen + 4,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("%03b. .... = Flags: %s", flags, flagsDesc),
					Filter:        fmt.Sprintf("ip.flags == 0x%X", flags),
					Start:         linkLayerLen + 6,
					Length:        1,
					DataSourceIdx: 0,
					Tree: []Tree{
						{
							Label:         fmt.Sprintf("0... .... = Reserved bit: %s", rbDesc),
							Filter:        fmt.Sprintf("ip.flags.rb == %d", rb),
							Start:         linkLayerLen + 6,
							Length:        1,
							DataSourceIdx: 0,
							Tree:          []Tree{},
							Severity:      "",
							Type:          "",
							Fnum:          926233912,
							URL:           "",
						},
						{
							Label:         fmt.Sprintf(".1.. .... = Don't fragment: %s", dfDesc),
							Filter:        fmt.Sprintf("ip.flags.df == %d", df),
							Start:         linkLayerLen + 6,
							Length:        1,
							DataSourceIdx: 0,
							Tree:          []Tree{},
							Severity:      "",
							Type:          "",
							Fnum:          926233912,
							URL:           "",
						},
						{
							Label:         fmt.Sprintf("..0. .... = More fragments: %s", mfDesc),
							Filter:        fmt.Sprintf("ip.flags.mf == %d", mf),
							Start:         linkLayerLen + 6,
							Length:        1,
							DataSourceIdx: 0,
							Tree:          []Tree{},
							Severity:      "",
							Type:          "",
							Fnum:          926233912,
							URL:           "",
						},
					},
					Severity: "",
					Type:     "",
					Fnum:     0,
					URL:      "",
				},
				{
					Label:         fmt.Sprintf("%s = Fragment Offset: %d", fragOffsetDesc, fragOffset),
					Filter:        fmt.Sprintf("ip.frag_offset == %d", fragOffset),
					Start:         linkLayerLen + 6,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Time to Live: %d", ttl),
					Filter:        fmt.Sprintf("ip.ttl == %d", ttl),
					Start:         linkLayerLen + 8,
					Length:        1,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Protocol: TCP (%d)", proto),
					Filter:        fmt.Sprintf("ip.proto == %d", proto),
					Start:         linkLayerLen + 9,
					Length:        1,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Header Checksum: 0x%x [validation disabled]", checksum),
					Filter:        fmt.Sprintf("ip.checksum == 0x%x", checksum),
					Start:         linkLayerLen + 10,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         "Header checksum status: Unverified",
					Filter:        "ip.checksum.status == \"Unverified\"",
					Start:         0,
					Length:        0,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Source Address: %s", srcIP),
					Filter:        fmt.Sprintf("ip.src == %s", srcIP),
					Start:         linkLayerLen + 12,
					Length:        4,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Destination Address: %s", dstIP),
					Filter:        fmt.Sprintf("ip.dst == %s", dstIP),
					Start:         linkLayerLen + 16,
					Length:        4,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
			},
			Severity: "",
			Type:     "proto",
			Fnum:     1052,
			URL:      "",
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
	return tree
}

// transportLayerTree 传输层
func transportLayerTree(transportLayer gopacket.TransportLayer) Tree {
	var tree Tree
	switch layer := transportLayer.(type) {
	case *layers.TCP:
		// 偏移量取连接层加网络层的长度Length
		linkLayerAndNetworkLayerLen := 14 + 20
		transportLayerLen := len(layer.Contents)
		payloadrLen := len(layer.Payload)
		seq := layer.Seq
		ack := layer.Ack
		srcPort := layer.SrcPort
		dstPort := layer.DstPort
		dataOffset := layer.DataOffset
		hdrLen := dataOffset * 4
		flags, flagsDesc := transportFlagsDesc(layer)
		flagsACK, flagsACKDesc := transportFlagsStatus(layer.ACK)
		flagsPSH, flagsPSHDesc := transportFlagsStatus(layer.PSH)
		window := layer.Window
		checksum := layer.Checksum
		urgent := layer.Urgent
		optionsLen, optionsDesc := transportOptions(layer.Options)
		payloadStr := bytesToHexString(layer.Payload)

		tree = Tree{
			Label:         fmt.Sprintf("Transmission Control Protocol, Src Port: %s, Dst Port: %s, Seq: %d, Ack: %d, Len: %d", srcPort, dstPort, seq, ack, payloadrLen),
			Filter:        "tcp",
			Start:         linkLayerAndNetworkLayerLen,
			Length:        transportLayerLen,
			DataSourceIdx: 0,
			Tree: []Tree{
				{
					Label:         fmt.Sprintf("Source Port: %s", srcPort),
					Filter:        fmt.Sprintf("tcp.srcport == %d", srcPort),
					Start:         linkLayerAndNetworkLayerLen,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Destination Port: %s", dstPort),
					Filter:        fmt.Sprintf("tcp.dstport == %d", dstPort),
					Start:         linkLayerAndNetworkLayerLen + 2,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("TCP Segment Len: %d", payloadrLen),
					Filter:        fmt.Sprintf("tcp.len == %d", payloadrLen),
					Start:         linkLayerAndNetworkLayerLen + 12,
					Length:        1,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Sequence Number: %d (relative sequence number)", seq),
					Filter:        fmt.Sprintf("tcp.seq == %d", seq),
					Start:         linkLayerAndNetworkLayerLen + 4,
					Length:        4,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Acknowledgment Number: %d (relative ack number)", ack),
					Filter:        fmt.Sprintf("tcp.ack == %d", ack),
					Start:         linkLayerAndNetworkLayerLen + 8,
					Length:        4,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("%04b .... = Header Length: %d bytes (%d)", dataOffset, hdrLen, dataOffset),
					Filter:        fmt.Sprintf("tcp.hdr_len == %d", hdrLen),
					Start:         linkLayerAndNetworkLayerLen + 12,
					Length:        1,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Flags: 0x%03X (%s)", flags, flagsDesc),
					Filter:        fmt.Sprintf("ip.frag_offset == 0x%03X", flags),
					Start:         linkLayerAndNetworkLayerLen + 12,
					Length:        2,
					DataSourceIdx: 0,
					Tree: []Tree{
						{
							Label:         fmt.Sprintf(".... ...%d .... = Acknowledgment: %s", flagsACK, flagsACKDesc),
							Filter:        fmt.Sprintf("tcp.flags.ack == %d", flagsACK),
							Start:         linkLayerAndNetworkLayerLen + 13,
							Length:        1,
							DataSourceIdx: 0,
							Tree:          []Tree{},
							Severity:      "",
							Type:          "",
							Fnum:          926233912,
							URL:           "",
						},
						{
							Label:         fmt.Sprintf(".... .... %d... = Push: %s", flagsPSH, flagsPSHDesc),
							Filter:        fmt.Sprintf("tcp.flags.push == %d", flagsPSH),
							Start:         linkLayerAndNetworkLayerLen + 13,
							Length:        1,
							DataSourceIdx: 0,
							Tree:          []Tree{},
							Severity:      "",
							Type:          "",
							Fnum:          926233912,
							URL:           "",
						},
					},
					Severity: "",
					Type:     "",
					Fnum:     0,
					URL:      "",
				},
				{
					Label:         fmt.Sprintf("Window: %d", window),
					Filter:        fmt.Sprintf("tcp.window_size_value == %d", window),
					Start:         linkLayerAndNetworkLayerLen + 14,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Calculated window size: %d", window),
					Filter:        fmt.Sprintf("tcp.window_size == %d", window),
					Start:         linkLayerAndNetworkLayerLen + 14,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Checksum: 0x%04x [unverified]", checksum),
					Filter:        fmt.Sprintf("tcp.checksum == 0x%04x", checksum),
					Start:         linkLayerAndNetworkLayerLen + 16,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         "Checksum Status: Unverified",
					Filter:        "tcp.checksum.status == \"Unverified\"",
					Start:         0,
					Length:        0,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Urgent Pointer: %d", urgent),
					Filter:        fmt.Sprintf("tcp.urgent_pointer == %d", urgent),
					Start:         linkLayerAndNetworkLayerLen + 18,
					Length:        2,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("Options: (%d bytes), %s", optionsLen, optionsDesc),
					Filter:        fmt.Sprintf("tcp.options == %d", optionsLen),
					Start:         linkLayerAndNetworkLayerLen + 20,
					Length:        int(optionsLen),
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
				{
					Label:         fmt.Sprintf("TCP payload (%d bytes)", payloadrLen),
					Filter:        fmt.Sprintf("tcp.payload == %s", payloadStr),
					Start:         linkLayerAndNetworkLayerLen + 32,
					Length:        payloadrLen,
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "",
					Fnum:          0,
					URL:           "",
				},
			},
			Severity: "",
			Type:     "proto",
			Fnum:     1052,
			URL:      "",
		}
	case *layers.UDP:
		log.Printf("-> UDP, length %d", len(layer.Payload))
	case *layers.UDPLite:
		log.Printf("-> UDPLite, length %d", len(layer.Payload))
	}

	return tree
}

// applicationLayerTree 应用层
func applicationLayerTree(applicationLayer gopacket.ApplicationLayer) Tree {
	var tree Tree
	switch layer := applicationLayer.(type) {
	case *layers.DNS:
		log.Printf("-> DNS,  %s", util.DnsData(layer))
	case *layers.SIP:
		log.Printf("-> SIP,  %s", layer.RequestURI)
	default:
		log.Printf("-> %s, length %d", layer.LayerType(), layer.Payload())
		if applicationHTTP(layer.LayerContents()) {
			log.Printf("-> HTTP,  %s", layer.LayerContents())
			// 偏移量取连接层加网络层加协议层的长度Length
			linkLayerAndNetworkLayerAndTransportLayerLen := 14 + 20 + 32
			length := len(layer.LayerContents())

			tree = Tree{
				Label:         "Hypertext Transfer Protocol",
				Filter:        "http",
				Start:         linkLayerAndNetworkLayerAndTransportLayerLen,
				Length:        length,
				DataSourceIdx: 0,
				Tree:          []Tree{},
				Severity:      "",
				Type:          "Chat",
				Fnum:          1052,
				URL:           "",
			}

			result := applicationHTTPProcess(string(layer.LayerContents()))
			for _, v := range result {
				tree.Tree = append(tree.Tree, Tree{
					Label:         v["label"].(string),
					Filter:        fmt.Sprintf("http.%s == %s", v["key"].(string), v["value"].(string)),
					Start:         linkLayerAndNetworkLayerAndTransportLayerLen + v["length"].(int),
					Length:        v["length"].(int),
					DataSourceIdx: 0,
					Tree:          []Tree{},
					Severity:      "",
					Type:          "Chat",
					Fnum:          1052,
					URL:           "",
				})
			}

		}
	}
	return tree
}
