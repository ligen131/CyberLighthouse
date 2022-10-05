package client

import (
	"CyberLighthouse/packet"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// DIGG [A/NS/CNAME/AAAA/MX] [domain] [--server=8.8.8.8] [--recursion=true] [--help]
type ClientFlagsOrigin struct {
	Record      string
	Url         string
	Server      string
	IsRecursion bool
}

type ClientFlags struct {
	OriginFlags   ClientFlagsOrigin
	f_Record      packet.RecordType
	f_Url         string
	f_Server      net.IP
	f_IsRecursion bool
}

func (f *ClientFlags) ParseFlags() {
	switch f.OriginFlags.Record {
	case "a":
		f.f_Record = packet.RECORD_A
	case "ns":
		f.f_Record = packet.RECORD_NS
	case "cname":
		f.f_Record = packet.RECORD_CNAME
	case "mx":
		f.f_Record = packet.RECORD_MX
	case "aaaa":
		f.f_Record = packet.RECORD_AAAA
	}
	f.f_Url = f.OriginFlags.Url
	f.f_Server = net.ParseIP(f.OriginFlags.Server)
	if f.f_Server == nil {
		f.f_Server = net.ParseIP("8.8.8.8")
	}
	f.f_IsRecursion = f.OriginFlags.IsRecursion
}

var queryTemplate []byte = []byte{0, 0, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0, 6,
	103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1}

type Client struct {
	send   packet.PacketGenerator
	recv   packet.PacketParser
	socket *net.UDPConn
}

func (c *Client) SendQuery(f *ClientFlags) (packet.PacketParser, int, net.UDPAddr, error) {
	var err error
	c.socket, err = net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   f.f_Server,
		Port: 53,
	})
	if err != nil {
		return packet.PacketParser{}, 0, net.UDPAddr{}, fmt.Errorf("Connect to server %s failed. error info = %v", f.f_Server.String(), err)
	}
	defer c.socket.Close()

	var tmp packet.PacketParser
	tmp.OriginData = queryTemplate
	err = tmp.Parse()
	if err != nil {
		return packet.PacketParser{}, 0, net.UDPAddr{}, fmt.Errorf("Template parse failed. Cannot get to this place! error info = %v", err)
	}
	tmp.Result.P_Queries[0].Q_Name = f.f_Url
	tmp.Result.P_Queries[0].Q_Type = f.f_Record
	tmp.Result.P_Header.H_Flags.F_RD = f.f_IsRecursion
	rand.Seed(time.Now().UnixNano())
	tmp.Result.P_Header.H_TransactionID = uint16(rand.Int31())
	c.send.Pkt = tmp.Result

	err = c.send.Generator()
	if err != nil {
		return packet.PacketParser{}, 0, net.UDPAddr{}, fmt.Errorf("UDP package generate failed. Please check your input URL. error info = %v", err)
	}

	_, err = c.socket.Write(c.send.Result)
	if err != nil {
		return packet.PacketParser{}, 0, net.UDPAddr{}, fmt.Errorf("Send data failed. error info = %v", err)
	}

	c.recv.OriginData = make([]byte, 4096)
	n, remoteAddr, err := c.socket.ReadFromUDP(c.recv.OriginData)
	if err != nil {
		return packet.PacketParser{}, 0, net.UDPAddr{}, fmt.Errorf("Data receive failed. error info = %v", err)
	}
	err = c.recv.Parse()
	if err != nil {
		return packet.PacketParser{}, 0, net.UDPAddr{}, fmt.Errorf("Received data parse failed. error info = %v", err)
	}

	return c.recv, n, (*remoteAddr), nil
}

func (c *Client) Query(f *ClientFlags) string {
	pkt, n, addr, err := c.SendQuery(f)
	if err != nil {
		return err.Error()
	}
	ans := fmt.Sprintf("Receive data from %s:%d, UDP package length = %d\nThe query result:\n---------------------------------\n", addr.IP.String(), addr.Port, n)
	s, err := pkt.Output()
	if err != nil {
		return fmt.Sprintf("Received data output failed. error info = %v", err)
	}
	ans += s + "---------------------------------\n"
	return ans
}
