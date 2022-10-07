package client

import (
	"CyberLighthouse/packet"
	"CyberLighthouse/util"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// DIGG [A/NS/CNAME/AAAA/MX] [domain] [--server=8.8.8.8] [--recursion=true] [--help]
type ClientFlagsOrigin struct {
	Record      string
	Url         string
	Server      string
	IsRecursion bool
	IsTCP       bool
	Retry       int
}

type ClientFlags struct {
	OriginFlags   ClientFlagsOrigin
	F_Record      packet.RecordType
	F_Url         string
	F_Server      net.IP
	F_IsRecursion bool
}

func (f *ClientFlags) ParseFlags() {
	switch f.OriginFlags.Record {
	case "a":
		f.F_Record = packet.RECORD_A
	case "ns":
		f.F_Record = packet.RECORD_NS
	case "cname":
		f.F_Record = packet.RECORD_CNAME
	case "mx":
		f.F_Record = packet.RECORD_MX
	case "aaaa":
		f.F_Record = packet.RECORD_AAAA
	}
	f.F_Url = f.OriginFlags.Url
	f.F_Server = net.ParseIP(f.OriginFlags.Server)
	if f.F_Server == nil {
		f.F_Server = net.ParseIP("8.8.8.8")
	}
	f.F_IsRecursion = f.OriginFlags.IsRecursion

	if f.OriginFlags.Retry < 0 {
		f.OriginFlags.Retry = 0
	}
}

var queryTemplate []byte = []byte{0, 0, 1, 32, 0, 1, 0, 0, 0, 0, 0, 0, 6,
	103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1}

type Client struct {
	IsTCP   bool
	Retry   int
	Timeout time.Duration
	running int
	Result  []packet.Packet
}

func (c *Client) send(IP net.IP, Port int, data []byte, callbackFunc func([]byte)) error {
	network := "udp"
	if c.IsTCP {
		network = "tcp"
	}
	socket, err := net.Dial(network, fmt.Sprintf("[%s]:%d", IP.String(), Port))
	defer socket.Close()
	if err != nil {
		return fmt.Errorf("[Client] Connect to server [%s]:%d failed. error info = %s\n", IP, Port, err.Error())
	}
	socket.SetDeadline(time.Now().Add(c.Timeout))
	if c.IsTCP {
		a, b := util.Uint16ToByte(uint16(len(data)))
		tmp := []byte{a, b}
		data = append(tmp, data...)
	}
	_, err = socket.Write(data)
	if err != nil {
		return fmt.Errorf("[Client] Write data failed. error info = %s\n", err.Error())
	}
	cnt := 0
	for {
		cnt++
		if cnt > 1 {
			socket.SetDeadline(time.Now().Add(time.Millisecond * 200))
		} else {
			socket.SetDeadline(time.Now().Add(c.Timeout))
		}
		data := make([]byte, 4096)
		n, err := socket.Read(data)
		if err != nil {
			break
		}
		fmt.Printf("[Client] Receive %s package from [%s]:%d, length = %d\n",
			strings.ToUpper(network), IP.String(), Port, n)
		if c.IsTCP {
			if len(data) < 2 {
				continue
			}
			data = data[2:]
		}
		if callbackFunc != nil {
			callbackFunc(data)
		}
	}
	if cnt == 1 {
		return errors.New("Empty response")
	}
	return nil
}

func (c *Client) Send(IP net.IP, Port int, data []byte, callbackFunc func([]byte)) {
	c.running++
	err := c.send(IP, Port, data, callbackFunc)
	if err != nil {
		for i := 0; i < c.Retry; i++ {
			fmt.Printf("Error occur while sending package. error info = %s. Retry %d times...\n", err.Error(), c.Retry-i)
			err := c.send(IP, Port, data, callbackFunc)
			if err == nil {
				break
			}
		}
	}
	c.running--
}

func (c *Client) dataCallback(data []byte) {
	p := packet.PacketParser{
		OriginData: data,
	}
	err := p.Parse()
	if err != nil {
		fmt.Printf("Received data parse failed. error info = %s", err.Error())
		return
	}
	c.Result = append(c.Result, p.Result)
}

func (c *Client) SendQuery(f *ClientFlags) (packet.Packet, error) {
	c.IsTCP = f.OriginFlags.IsTCP
	if c.Timeout < time.Millisecond*200 {
		c.Timeout = time.Second
	}

	var tmp packet.PacketParser
	tmp.OriginData = queryTemplate
	err := tmp.Parse()
	if err != nil {
		return packet.Packet{}, fmt.Errorf("Template parse failed. Cannot get to this place! error info = %v", err)
	}
	tmp.Result.P_Queries[0].Q_Name = f.F_Url
	tmp.Result.P_Queries[0].Q_Type = f.F_Record
	tmp.Result.P_Header.H_Flags.F_RD = f.F_IsRecursion
	rand.Seed(time.Now().UnixNano())
	tmp.Result.P_Header.H_TransactionID = uint16(rand.Int31())
	send := packet.PacketGenerator{
		Pkt: tmp.Result,
	}

	err = send.Generator()
	if err != nil {
		return packet.Packet{}, fmt.Errorf("Package generate failed. Please check your input URL. error info = %v", err)
	}

	c.Result = []packet.Packet{}
	c.Send(f.F_Server, 53, send.Result, c.dataCallback)
	if len(c.Result) == 0 {
		return packet.Packet{}, errors.New("Empty or no valid response.")
	}
	p := c.Result[0]
	for i := range c.Result {
		if i > 0 {
			p.P_Header.H_AnswerRRs += c.Result[i].P_Header.H_AnswerRRs
			p.P_Header.H_AuthorityRRs += c.Result[i].P_Header.H_AuthorityRRs
			p.P_Header.H_AdditionalRRs += c.Result[i].P_Header.H_AdditionalRRs

			p.P_Answers = append(p.P_Answers, c.Result[i].P_Answers...)
			p.P_Authority = append(p.P_Authority, c.Result[i].P_Authority...)
			p.P_Additional = append(p.P_Additional, c.Result[i].P_Additional...)
		}
	}
	return p, nil
}

func (c *Client) Query(f *ClientFlags) string {
	c.Timeout = time.Second * 3
	c.IsTCP = f.OriginFlags.IsTCP
	c.Retry = f.OriginFlags.Retry
	var err error
	p := packet.PacketParser{}
	p.Result, err = c.SendQuery(f)
	if err != nil {
		return err.Error()
	}
	ans := "The query result:\n---------------------------------\n"
	s := p.Result.Output(true)
	ans += s + "---------------------------------\n"
	return ans
}
