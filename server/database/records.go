package database

import (
	"CyberLighthouse/packet"
	"errors"
	"net"
)

type DbRecordA struct {
	Name        string `bson:"Name"`
	ExpiredTime int64  `bson:"ExpiredTime"`
	Class       int    `bson:"Class,omitempty"`
	TimeToLive  int    `bson:"TTL,omitempty"`
	IP          string `bson:"IP,omitempty"`
}

func (r *DbRecordA) PacketRecordToDbRecord(pr *packet.PacketRecords) error {
	if pr.R_Type != packet.RECORD_A {
		return errors.New("not A record")
	}
	IP := net.IPv4(pr.R_Data.R_A_IP[0], pr.R_Data.R_A_IP[1],
		pr.R_Data.R_A_IP[2], pr.R_Data.R_A_IP[3])
	*r = DbRecordA{
		Name:       pr.R_Name,
		Class:      int(pr.R_Class),
		TimeToLive: int(pr.R_TimeToLive),
		IP:         IP.String(),
	}
	return nil
}

func (r *DbRecordA) DbRecordToPacketRecord() (packet.PacketRecords, error) {
	IP := net.ParseIP(r.IP)
	l := len(IP)
	if IP == nil || l < 4 {
		return packet.PacketRecords{}, errors.New("Invalid IP in database")
	}
	var _IP [4]byte
	_IP[0] = IP[l-4]
	_IP[1] = IP[l-3]
	_IP[2] = IP[l-2]
	_IP[3] = IP[l-1]
	return packet.PacketRecords{
		R_Name:       r.Name,
		R_Type:       packet.RECORD_A,
		R_Class:      packet.ClassType(r.Class),
		R_TimeToLive: uint32(r.TimeToLive),
		R_DataLength: 4,
		R_Data: packet.PacketRecordData{
			R_A_IP: _IP,
		},
	}, nil
}
