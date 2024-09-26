package util

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// FormatPacketData should be used to format packet data.
func FormatPacketData(data []byte) string {
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

// HexDump produces a wireshark-like hexdump, with an option to set the left and
// right delimiter used for the ascii section. This is a cheesy implementation using
// a regex to change the golang hexdump output.
func HexDump(data []byte, leftAsciiDelimiter, rightAsciiDelimiter string) string {
	re := regexp.MustCompile(`(?m)^(.{60})\|(.+?)\|$`) // do each line
	// Output:
	// 00000000  47 6f 20 69 73 20 61 6e  20 6f 70 65 6e 20 73 6f  |Go is an open so|
	// 00000010  75 72 63 65 20 70 72 6f  67 72 61 6d 6d 69 6e 67  |urce programming|
	// 00000020  20 6c 61 6e 67 75 61 67  65 2e                    | language.|
	res := hex.Dump(data)
	res = re.ReplaceAllString(res, fmt.Sprintf(`${1}%s${2}%s`, leftAsciiDelimiter, rightAsciiDelimiter))

	return strings.TrimRight(res, "\n")
}
