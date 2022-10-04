package main

import (
	"CyberLighthouse/packet"
	"CyberLighthouse/util"
	"fmt"
	"net"
)

func main() {
	addr := net.UDPAddr{
		Port: 53,
		IP:   net.IPv4(127, 0, 0, 1),
	}
	u, _ := net.ListenUDP("udp", &addr)
	fmt.Printf("Listening on %s:%d...\n", addr.IP.String(), addr.Port)

	for {
		tmp := make([]byte, 512)
		_, _, err := u.ReadFrom(tmp[:])
		if err != nil {
			fmt.Println("Error UDP")
			continue
		}
		// fmt.Println(n, addr, tmp)
		var pk packet.PacketParser
		pk.OriginData = tmp
		err = pk.Parse()
		if err != nil {
			util.ErrorPrint(err, tmp, "Parse failed.")
		} else {
			err = pk.Output()
			if err != nil {
				util.ErrorPrint(err, tmp, "Output failed.")
			}
		}
	}
}
