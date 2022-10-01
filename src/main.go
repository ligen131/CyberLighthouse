package main

import (
	"fmt"
	"net"
)

func main() {
	addr := net.UDPAddr{
		Port: 53,
		IP:   net.IPv4(127, 0, 0, 1),
	}
	u, _ := net.ListenUDP("udp", &addr)

	for {
		tmp := make([]byte, 1024)
		n, addr, err := u.ReadFrom(tmp[:])
		if err != nil {
			fmt.Println("Error UDP")
			continue
		}
		fmt.Println(n, addr, tmp)
	}
}
