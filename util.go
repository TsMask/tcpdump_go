// Copyright 2024 the u-root Authors. All rights reserved
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

//go:generate go run gen.go

// wellKnownPorts returns the well-known name of the port or the port number itself.
func (cmd cmd) wellKnownPorts(port string) string {
	if name, ok := wellKnownPortsMap[port]; ok && !cmd.Opts.Numerical {
		return name
	}

	return port
}

// listDevices lists all the network devices which can be listed to.
func listDevices() error {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	for idx, link := range devices {
		fmt.Printf("%d: %s - %s\n", idx, link.Name, link.Description)
		if len(link.Addresses) > 0 {
			for _, address := range link.Addresses {
				if address.IP != nil {
					fmt.Printf("\tIP Address: %s\n", address.IP)
				}
			}
		} else {
			fmt.Println("\tNo IP Address found.")
		}
	}

	return nil
}

// containsIPAddress returns true if the device has the given IP address.
func containsIPAddress(device pcap.Interface, ip string) bool {
	for _, address := range device.Addresses {
		if address.IP != nil && address.IP.String() == ip {
			return true
		}
	}
	return false
}

// parseTimeStamp returns the timestamp in the format specified by the user using the -t, -tt, -ttt, -tttt, -ttttt, -nano flags.
func (cmd *cmd) parseTimeStamp(currentTimestamp, lastTimeStamp time.Time) string {
	if cmd.Opts.T {
		return ""
	}
	if cmd.Opts.TT {
		return fmt.Sprintf("%d", currentTimestamp.Unix())
	}
	if cmd.Opts.TTT {
		diff := currentTimestamp.Sub(lastTimeStamp)
		if cmd.Opts.TimeStampInNanoSeconds {
			return fmt.Sprintf("%02d:%02d:%02d.%09d", int(diff.Hours()), int(diff.Minutes())%60, int(diff.Seconds())%60, diff.Nanoseconds()%1e9)
		}

		return fmt.Sprintf("%02d:%02d:%02d.%06d", int(diff.Hours()), int(diff.Minutes())%60, int(diff.Seconds())%60, diff.Microseconds()%1e6)
	}
	if cmd.Opts.TTTT {
		diff := currentTimestamp.Sub(lastTimeStamp)
		return fmt.Sprintf("%02d:%02d:%02d", int(diff.Hours()), int(diff.Minutes())%60, int(diff.Seconds())%60)
	}
	return currentTimestamp.Format("15:04:05.000000")
}

func formatPacketData(data []byte) string {
	var result string
	for i := 0; i < len(data); i += 16 {
		// Print the offset
		result += fmt.Sprintf("0x%04x:  ", i)

		// Print the hex values
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				result += fmt.Sprintf("%02x", data[i+j])
			} else {
				result += "  "
			}
			if j%2 == 1 {
				result += " "
			}
		}
		result += "\n"
	}
	return result
}
