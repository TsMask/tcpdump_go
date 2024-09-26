package util

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/gopacket/gopacket/layers"
)

// tcpData returns a string representation of the TCP layer.
func TcpData(layer *layers.TCP) (string, string) {
	return tcpFlags(*layer), tcpOptions(layer.Options)
}

// tcpFlags returns a string representation of the TCP flags.
func tcpFlags(layer layers.TCP) string {
	var flags string
	if layer.PSH {
		flags += "P"
	}
	if layer.FIN {
		flags += "F"
	}
	if layer.SYN {
		flags += "S"
	}
	if layer.RST {
		flags += "R"
	}
	if layer.URG {
		flags += "U"
	}
	if layer.ECE {
		flags += "E"
	}
	if layer.CWR {
		flags += "C"
	}
	if layer.NS {
		flags += "N"
	}
	if layer.ACK {
		flags += "."
	}

	return flags
}

// tcpOptions returns a string representation of the TCP options.
func tcpOptions(options []layers.TCPOption) string {
	var opts string

	for _, opt := range options {
		opts += tcpOptionToString(opt) + ","
	}

	return strings.TrimRight(opts, ",")
}

// tcpOptionToString returns a string representation of the TCP option.
func tcpOptionToString(opt layers.TCPOption) string {
	if opt.OptionType == layers.TCPOptionKindMSS && len(opt.OptionData) == 2 {
		return fmt.Sprintf("%s val %v",
			opt.OptionType,
			binary.BigEndian.Uint16(opt.OptionData))
	}

	if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) == 8 {
		return fmt.Sprintf("%s val %v",
			opt.OptionType,
			binary.BigEndian.Uint32(opt.OptionData[:4]))
	}

	return fmt.Sprint(opt.OptionType)
}
