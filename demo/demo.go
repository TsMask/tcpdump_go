package demo

import (
	"time"

	"github.com/gopacket/gopacket"
)

func Demo(packet gopacket.Packet, num int, lastPkgTimeStamp time.Time) {
	if true {
		networkAnalyzerFile(packet, num)
	}
	if false {
		networkAnalyzer(packet, num)
	}
	if false {
		networkParse(packet)
	}
}
