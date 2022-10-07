package main

import (
	"CyberLighthouse/packet"
	"CyberLighthouse/util"
	"fmt"
	"net"
)

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

func checkByteSame(n int, a []byte, b []byte) bool {
	n = min(n, min(len(a), len(b)))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

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
		var pk packet.PacketParser
		pk.OriginData = tmp
		err = pk.Parse()
		if err != nil {
			util.ErrorPrint(err, tmp, "Parse failed.")
		} else {
			fmt.Println(pk.Result.Output(false))
		}

		var ge packet.PacketGenerator
		ge.Pkt = pk.Result
		err = ge.Generator()
		if err != nil {
			util.ErrorPrint(err, nil, "Generate failed.")
		}
		fmt.Println(pk.OriginData[:len(ge.Result)])
		fmt.Println(ge.Result, len(ge.Result))
		if !checkByteSame(len(ge.Result), pk.OriginData, ge.Result) {
			fmt.Println("Generate query wrong.")
		}
	}
}
