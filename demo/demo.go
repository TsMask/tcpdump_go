package demo

import (
	"time"

	"github.com/gopacket/gopacket"
)

func Demo(packet gopacket.Packet, num int, lastPkgTimeStamp time.Time) {
	if false {
		networkAnalyzer(packet, num)
	}
	if true {
		networkParse(packet)
	}
}
