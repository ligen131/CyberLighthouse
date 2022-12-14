package server

import (
	"CyberLighthouse/packet"
	"CyberLighthouse/util"
	"client/client"
	"errors"
	"fmt"
	"net"
	"server/database"
	"time"

	"github.com/gogf/greuse"
)

type ServerFlags struct {
	IsRecursion bool
	TCPenable   bool
	UDPenable   bool
}

type ServerCacheRecord struct {
	RecordA     packet.PacketRecords
	expiredTime time.Time
}

type Server struct {
	cache            map[string]([]ServerCacheRecord)
	d                database.DB
	cacheUseDatabase bool
}

const dbName string = "DnsServer"

var rootServer []net.IP = []net.IP{
	net.ParseIP("192.5.6.30"),
	net.ParseIP("192.33.14.30"),
	net.ParseIP("192.26.92.30"),
	net.ParseIP("192.31.80.30"),
	net.ParseIP("192.12.94.30"),
	net.ParseIP("192.35.51.30"),
	net.ParseIP("192.42.93.30"),
	net.ParseIP("192.54.112.30"),
	net.ParseIP("192.43.172.30"),
	net.ParseIP("192.48.79.30"),
	net.ParseIP("192.52.178.30"),
	net.ParseIP("192.41.162.30"),
	net.ParseIP("192.55.83.30"),
}

func (s *Server) addCache(url string, r packet.PacketRecords) {
	if url == "" {
		url = "."
	}
	if url[len(url)-1] != '.' {
		url += "."
	}
	if !s.cacheUseDatabase {
		if s.cache[url] == nil {
			s.cache[url] = []ServerCacheRecord{}
		}
		s.cache[url] = append(s.cache[url], ServerCacheRecord{r, time.Now().Add(time.Second * time.Duration(r.R_TimeToLive))})
	} else {
		tmp := database.DbRecordA{}
		tmp.PacketRecordToDbRecord(&r)
		err := s.d.AddRecordA(&tmp)
		if err != nil {
			fmt.Printf("[Cache] Error while add cache into database. error info = %s\n", err.Error())
		}
	}
}

func (s *Server) queryCache(url string) ([]packet.PacketRecords, error) {
	if url == "" {
		url = "."
	}
	if url[len(url)-1] != '.' {
		url += "."
	}
	ans := []packet.PacketRecords{}
	if !s.cacheUseDatabase {
		tmp := s.cache[url]
		for i := range tmp {
			if tmp[i].expiredTime.After(time.Now()) {
				ans = append(ans, tmp[i].RecordA)
			}
		}
	} else {
		tmp, err := s.d.QueryRecords(url)
		if err != nil {
			fmt.Printf("[Cache] Error while query records in the database. error info = %s\n", err.Error())
			return nil, err
		}
		for i := range tmp {
			a, err := tmp[i].DbRecordToPacketRecord()
			if err != nil {
				fmt.Printf("[Cache] Record error. error info = %s\n", err.Error())
				continue
			}
			ans = append(ans, a)
		}
	}
	if len(ans) == 0 {
		return ans, errors.New("Cache not found or have expired.")
	}
	fmt.Printf("Read cache %s, len = %d\n", url, len(ans))
	for i := range ans {
		fmt.Println(ans[i].R_Data.R_A_IP)
	}
	return ans, nil
}

func (s *Server) addManyCache(r *[]packet.PacketRecords) {
	for i := range *r {
		if (*r)[i].R_Type == packet.RECORD_A {
			s.addCache((*r)[i].R_Name, (*r)[i])
		}
	}
}

func (s *Server) checkPacketRecords(r *[]packet.PacketRecords, send *packet.PacketGenerator, currentServer net.IP) error {
	for i := range *r {
		if (*r)[i].R_Name == send.Pkt.P_Queries[0].Q_Name {
			if (*r)[i].R_Type == send.Pkt.P_Queries[0].Q_Type {
				send.Pkt.P_Header.H_AnswerRRs++
				send.Pkt.P_Answers = append(send.Pkt.P_Answers, (*r)[i])
			}
		}
	}
	if send.Pkt.P_Header.H_AnswerRRs != 0 {
		return nil
	}
	return errors.New("Record not found.")
}

func (s *Server) nextRecuFromA(r *[]packet.PacketRecords, send *packet.PacketGenerator, currentServer net.IP, isRecursion bool) error {
	for i := range *r {
		if (*r)[i].R_Type == packet.RECORD_A || (*r)[i].R_Type == packet.RECORD_AAAA {
			addr := net.IP{}
			if (*r)[i].R_Type == packet.RECORD_A {
				addr = net.IPv4((*r)[i].R_Data.R_A_IP[0], (*r)[i].R_Data.R_A_IP[1],
					(*r)[i].R_Data.R_A_IP[2], (*r)[i].R_Data.R_A_IP[3])
			} else {
				addr = net.ParseIP(fmt.Sprintf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x",
					(*r)[i].R_Data.R_AAAA_IP[0], (*r)[i].R_Data.R_AAAA_IP[1],
					(*r)[i].R_Data.R_AAAA_IP[2], (*r)[i].R_Data.R_AAAA_IP[3],
					(*r)[i].R_Data.R_AAAA_IP[4], (*r)[i].R_Data.R_AAAA_IP[5],
					(*r)[i].R_Data.R_AAAA_IP[6], (*r)[i].R_Data.R_AAAA_IP[7]))
			}
			s.recursion(send, addr, isRecursion)
			if send.Pkt.P_Header.H_AnswerRRs != 0 {
				return nil
			}
		}
	}
	return errors.New("Record not found.")
}

func (s *Server) nextRecuFromNS(r *[]packet.PacketRecords, send *packet.PacketGenerator, currentServer net.IP, isRecursion bool) error {
	for i := range *r {
		if (*r)[i].R_Type == packet.RECORD_NS {
			cache, err := s.queryCache((*r)[i].R_Data.R_NS_Name)
			if err == nil {
				s.nextRecuFromA(&cache, send, currentServer, isRecursion)
				if send.Pkt.P_Header.H_AnswerRRs != 0 {
					return nil
				}
			}
			c := client.Client{
				IsTCP: false,
				Retry: 2,
			}
			clientFlags := client.ClientFlags{
				F_Record:      packet.RECORD_A,
				F_Server:      currentServer,
				F_Url:         (*r)[i].R_Data.R_NS_Name,
				F_IsRecursion: isRecursion,
			}
			recv, err := c.SendQuery(&clientFlags)
			if err != nil {
				continue
			}

			s.addManyCache(&recv.P_Answers)
			s.addManyCache(&recv.P_Authority)
			s.addManyCache(&recv.P_Additional)

			s.nextRecuFromA(&recv.P_Answers, send, currentServer, isRecursion)
			s.nextRecuFromA(&recv.P_Authority, send, currentServer, isRecursion)
			s.nextRecuFromA(&recv.P_Additional, send, currentServer, isRecursion)
		}
		if send.Pkt.P_Header.H_AnswerRRs != 0 {
			return nil
		}
	}
	return errors.New("Record not found.")
}

func (s *Server) recursion(send *packet.PacketGenerator, currentServer net.IP, isRecursion bool) error {
	cache, err := s.queryCache(send.Pkt.P_Queries[0].Q_Name)
	if send.Pkt.P_Queries[0].Q_Type == packet.RECORD_A && err == nil {
		s.checkPacketRecords(&cache, send, currentServer)
		if send.Pkt.P_Header.H_AnswerRRs != 0 {
			send.Pkt.P_Header.H_Flags.F_rcode = packet.RCODE_NOERROR
			return nil
		}
		s.nextRecuFromA(&cache, send, currentServer, isRecursion)
		if send.Pkt.P_Header.H_AnswerRRs != 0 {
			send.Pkt.P_Header.H_Flags.F_rcode = packet.RCODE_NOERROR
			return nil
		}
	}
	c := client.Client{}
	clientFlags := client.ClientFlags{
		F_Record:      send.Pkt.P_Queries[0].Q_Type,
		F_Server:      currentServer,
		F_Url:         send.Pkt.P_Queries[0].Q_Name,
		F_IsRecursion: isRecursion,
	}
	recv, err := c.SendQuery(&clientFlags)

	if err != nil {
		send.Pkt.P_Header.H_Flags.F_rcode = recv.P_Header.H_Flags.F_rcode
		return err
	}

	s.addManyCache(&recv.P_Answers)
	s.addManyCache(&recv.P_Authority)
	s.addManyCache(&recv.P_Additional)

	if !isRecursion {
		send.Pkt.P_Header.H_QueriesCount = recv.P_Header.H_QueriesCount
		send.Pkt.P_Header.H_AnswerRRs = recv.P_Header.H_AnswerRRs
		send.Pkt.P_Header.H_AuthorityRRs = recv.P_Header.H_AuthorityRRs
		send.Pkt.P_Header.H_AdditionalRRs = recv.P_Header.H_AdditionalRRs
		send.Pkt.P_Answers = recv.P_Answers
		send.Pkt.P_Authority = recv.P_Authority
		send.Pkt.P_Additional = recv.P_Additional
		return nil
	}

	s.checkPacketRecords(&recv.P_Answers, send, currentServer)
	s.checkPacketRecords(&recv.P_Authority, send, currentServer)
	s.checkPacketRecords(&recv.P_Additional, send, currentServer)
	if send.Pkt.P_Header.H_AnswerRRs != 0 {
		send.Pkt.P_Header.H_Flags.F_rcode = packet.RCODE_NOERROR
		return nil
	}

	s.nextRecuFromA(&recv.P_Answers, send, currentServer, isRecursion)
	s.nextRecuFromA(&recv.P_Authority, send, currentServer, isRecursion)
	s.nextRecuFromA(&recv.P_Additional, send, currentServer, isRecursion)
	if send.Pkt.P_Header.H_AnswerRRs != 0 {
		send.Pkt.P_Header.H_Flags.F_rcode = packet.RCODE_NOERROR
		return nil
	}

	s.nextRecuFromNS(&recv.P_Answers, send, currentServer, isRecursion)
	s.nextRecuFromNS(&recv.P_Authority, send, currentServer, isRecursion)
	s.nextRecuFromNS(&recv.P_Additional, send, currentServer, isRecursion)
	if send.Pkt.P_Header.H_AnswerRRs != 0 {
		send.Pkt.P_Header.H_Flags.F_rcode = packet.RCODE_NOERROR
		return nil
	}

	return errors.New("Record not found.")
}

func (s *Server) Execute(size int, addr net.Addr, data []byte, f ServerFlags, writeFunc func([]byte, net.Addr)) {
	pkt := packet.PacketParser{OriginData: data}
	err := pkt.Parse()
	if err != nil {
		fmt.Printf("[Server] Error when parsing package. error info = %s\n", err.Error())
		return
	}

	send := packet.PacketGenerator{Pkt: pkt.Result}
	send.Pkt.P_Header.H_Flags.F_QR = true
	send.Pkt.P_Header.H_Flags.F_RA = f.IsRecursion
	send.Pkt.P_Header.H_AnswerRRs = 0
	send.Pkt.P_Header.H_AuthorityRRs = 0
	send.Pkt.P_Header.H_AdditionalRRs = 0
	send.Pkt.P_Answers = []packet.PacketRecords{}
	send.Pkt.P_Authority = []packet.PacketRecords{}
	send.Pkt.P_Additional = []packet.PacketRecords{}
	for i := range rootServer {
		s.recursion(&send, rootServer[i], f.IsRecursion)
		if send.Pkt.P_Header.H_AnswerRRs != 0 {
			break
		}
	}

	err = send.Generator()
	if err != nil {
		fmt.Printf("[Server] Error while generating sending package. error info = %s\n", err.Error())
		return
	}

	if writeFunc != nil {
		writeFunc(send.Result, addr)
	} else {
		fmt.Println("[Server] Error write package function is nil")
	}
}

const listeningLocalAddr string = "127.0.0.1:53"

func (s *Server) udpListen(f *ServerFlags) {
	socket, err := greuse.ListenPacket("udp", listeningLocalAddr)
	if err != nil {
		fmt.Printf("[Server] Error while UDP server listening %s, error info = %s\n", listeningLocalAddr, err.Error())
		return
	}
	defer socket.Close()
	fmt.Printf("[Server] UDP server listening on %s...\n", socket.LocalAddr().String())
	for {
		data := make([]byte, 4096)
		n, addr, err := socket.ReadFrom(data)
		if err != nil {
			break
		}
		fmt.Printf("[Server] Read package from %s, length = %d\n", addr.String(), n)
		go s.Execute(n, addr, data, *f, func(data []byte, addr net.Addr) {
			_, err := socket.WriteTo(data, addr)
			if err != nil {
				fmt.Printf("[Server] Error while write UDP package to %s error info = %s\n", addr.String(), err.Error())
			}
		})
	}
}

func (s *Server) tcpRead(socket net.Conn, f *ServerFlags) {
	for {
		data := make([]byte, 4096)
		_, err := socket.Read(data)
		if err != nil {
			break
		}
		if len(data) < 2 {
			continue
		}
		data = data[2:]
		n := len(data)
		fmt.Printf("[Server] Read TCP package from %s, length = %d\n", socket.RemoteAddr().String(), n)
		go s.Execute(n, socket.RemoteAddr(), data, *f, func(data []byte, addr net.Addr) {
			a, b := util.Uint16ToByte(uint16(len(data)))
			tmp := []byte{a, b}
			data = append(tmp, data...)
			_, err := socket.Write(data)
			if err != nil {
				fmt.Printf("[Server] Error while write UDP package to %s error info = %s\n", addr.String(), err.Error())
			}
		})
	}
}

func (s *Server) tcpListen(f *ServerFlags) {
	listener, err := greuse.Listen("tcp", listeningLocalAddr)
	if err != nil {
		fmt.Printf("[Server] Error while TCP server listening %s, error info = %s\n", listeningLocalAddr, err.Error())
		return
	}
	defer listener.Close()
	fmt.Printf("[Server] TCP server listening on %s...\n", listener.Addr().String())
	for {
		socket, err := listener.Accept()
		if err != nil {
			fmt.Printf("[Server] Error while accept TCP connection from %s, error info = %s\n", socket.RemoteAddr().String(), err.Error())
			continue
		}
		go s.tcpRead(socket, f)
	}
}

func (s *Server) Start(f ServerFlags) {
	err := s.d.ConnectToDB(dbName)
	if err != nil {
		fmt.Printf("[Server] Error while connecting to database, use cache in the memory. error info = %s", err.Error())
		s.cacheUseDatabase = false
		s.cache = make(map[string]([]ServerCacheRecord))
	} else {
		s.cacheUseDatabase = true
	}

	if !f.TCPenable && !f.UDPenable {
		fmt.Println("[Server] You cannot set both TCP and UDP modes disable.")
		return
	}
	if !f.TCPenable {
		s.udpListen(&f)
	} else if !f.UDPenable {
		s.tcpListen(&f)
	} else {
		go s.udpListen(&f)
		s.tcpListen(&f)
	}
}
