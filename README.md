# tcpdump_go

tcpdump learn reference u-root

I'm windows debugging. Install `npcap.exe` or `libpcap` on your system.

````bash
# show network interface
go run . -D

# windows run
# couldn't load wpcap.dll
go run . -i "\Device\NPF_{5B164303-C40F-4CEA-9873-993ABE4018B9}" -n -v -number

# Liunx
cd build . -o tcpdump_go
sudo ./tcpdump_go -i eth0 -n -v -number
````

## reference

- [tcpdump](https://www.tcpdump.org/linktypes.html)
- [gopacket](https://pkg.go.dev/github.com/gopacket/gopacket)
- [go-pcap](https://pkg.go.dev/github.com/packetcap/go-pcap)
- [net-pack](https://github.com/ashmitsharp/net-pack)
- [u-root](https://github.com/u-root/u-root)
- [tcpdump_go](https://github.com/ba0gu0/tcpdump_go)
- [go-netflow](https://github.com/rfyiamcool/go-netflow/tree/master)

UI
- [termshark](https://github.com/gcla/termshark/blob/master/README.md)
- [cuishark](https://github.com/cuishark/cuishark/blob/master/cgocuishark/cgocuishark.go)