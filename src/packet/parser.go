package packet

import (
	"CyberLighthouse/constant"
	"CyberLighthouse/util"
	"fmt"
)

type PacketParser struct {
	OriginData []byte
	Result     Packet
}

func (p *PacketParser) parsePacketHeaderFlags(data []byte) (PacketHeaderFlags, error) {
	if len(data) != 2 {
		return PacketHeaderFlags{},
			fmt.Errorf(constant.ERROR_PACKET_HEADER_FLAG_TOO_SHORT)
	}
	var flags PacketHeaderFlags
	a := uint8(data[0])
	b := uint8(data[1])
	flags.F_QR = bool((a & (1 << 7)) != 0)
	flags.F_Opcode = OpcodeType((a & 0b01111000) >> 3)
	flags.F_AA = bool((a & (1 << 2)) != 0)
	flags.F_TC = bool((a & (1 << 1)) != 0)
	flags.F_RD = bool((a & (1 << 0)) != 0)

	flags.F_RA = bool((b & (1 << 7)) != 0)
	flags.F_Z = bool((b & (1 << 6)) != 0)
	flags.F_AD = bool((b & (1 << 5)) != 0)
	flags.F_CD = bool((b & (1 << 4)) != 0)
	flags.F_rcode = RcodeType(b & 0b00001111)
	return flags, nil
}

func (p *PacketParser) parsePacketHeader(data []byte) (PacketHeader, error) {
	if len(data) != 12 {
		return PacketHeader{},
			fmt.Errorf(constant.ERROR_PACKET_HEADER_TOO_SHORT)
	}
	var header PacketHeader
	var err error
	header.H_TransactionID = util.ByteToUint16(data[0:2])

	header.H_Flags, err = p.parsePacketHeaderFlags(data[2:4])
	if err != nil {
		return PacketHeader{}, err
	}

	header.H_QueriesCount = util.ByteToUint16(data[4:6])
	header.H_AnswerRRs = util.ByteToUint16(data[6:8])
	header.H_AuthorityRRs = util.ByteToUint16(data[8:10])
	header.H_AdditionalRRs = util.ByteToUint16(data[10:12])
	return header, nil
}

// return
// @ans string
// @endIndex int
// @err error
func (p *PacketParser) parseName(startIndex int) (string, int, error) {
	data := &p.OriginData
	ans := ""
	var length uint8 = 0
	var i int
	endIndex := -1
	isFirst := true
	for i = startIndex; i < len(*data); i++ {
		b := (*data)[i]
		if length == 0 {
			if b == 0 {
				break
			}
			if (b & 0b11000000) == 0b11000000 {
				if i+1 >= len(*data) {
					return ans, i, fmt.Errorf(constant.ERROR_NAME_POINTER_WRONG)
				}
				if endIndex == -1 {
					endIndex = i + 2
				}
				i = int(util.Byte2ToUint16(b^0b11000000, (*data)[i+1])) - 1
				continue
			}
			if !isFirst {
				ans += "."
			}
			length = uint8(b)
		} else {
			isFirst = false
			if b == 0 {
				return ans, i, fmt.Errorf(constant.ERROR_NAME_LENGTH_WRONG)
			}
			ans += string(b)
			length--
		}
	}
	if length != 0 {
		return ans, i, fmt.Errorf(constant.ERROR_NAME_NOT_END_BY_ZERO)
	}
	if endIndex == -1 {
		endIndex = i + 1
	}
	if len(ans) > 0 && ans[len(ans)-1] != '.' {
		ans += "."
	}
	if ans == "" {
		ans = "<Root>"
	}
	return ans, endIndex, nil
}

// return
// @ans PacketQueries
// @endIndex int
// @err error
func (p *PacketParser) parsePacketQueries(startIndex int) (PacketQueries, int, error) {
	data := &p.OriginData
	var i int
	var err error
	var q PacketQueries
	q.Q_Name, i, err = p.parseName(startIndex)
	if err != nil {
		return PacketQueries{}, i, err
	}
	if i+4 > len((*data)) {
		return PacketQueries{}, i, fmt.Errorf(constant.ERROR_PACKET_QUERIES_TOO_SHORT)
	}
	q.Q_Type = RecordType(util.ByteToUint16((*data)[i : i+2]))
	q.Q_Class = ClassType(util.ByteToUint16((*data)[i+2 : i+4]))
	return q, i + 4, nil
}

func (p *PacketParser) parsePacketRecordData(r *PacketRecords) (PacketRecordData, error) {
	var ans PacketRecordData
	var err error
	var s string
	var i int
	ans.R_originData = p.OriginData[r.R_dataStartIndex : r.R_dataStartIndex+int(r.R_DataLength)]
	switch r.R_Type {
	case RECORD_A:
		{
			// IPv4 Address. Format = 255.255.255.255
			ans.R_A_IP = [4]byte{
				p.OriginData[r.R_dataStartIndex],
				p.OriginData[r.R_dataStartIndex+1],
				p.OriginData[r.R_dataStartIndex+2],
				p.OriginData[r.R_dataStartIndex+3],
			}
		}
	case RECORD_NS:
		{
			s, i, err = p.parseName(r.R_dataStartIndex)
			if err != nil {
				return ans, err
			}
			ans.R_NS_Name = s
			if i != r.R_dataStartIndex+int(r.R_DataLength) {
				return ans, fmt.Errorf(constant.ERROR_PACKET_RECORD_DATA_LENGTH_WRONG)
			}
		}
	case RECORD_CNAME:
		{
			s, i, err = p.parseName(r.R_dataStartIndex)
			if err != nil {
				return ans, err
			}
			ans.R_CNAME_Name = s
			if i != r.R_dataStartIndex+int(r.R_DataLength) {
				return ans, fmt.Errorf(constant.ERROR_PACKET_RECORD_DATA_LENGTH_WRONG)
			}
		}
	case RECORD_MX:
		{
			ans.R_MX.D_Preference =
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex : r.R_dataStartIndex+2])
			s, i, err = p.parseName(r.R_dataStartIndex + 2)
			if err != nil {
				return ans, err
			}
			ans.R_MX.D_Name = s
			if i != r.R_dataStartIndex+int(r.R_DataLength) {
				return ans, fmt.Errorf(constant.ERROR_PACKET_RECORD_DATA_LENGTH_WRONG)
			}
		}
	case RECORD_AAAA:
		{
			// IPv6 Address. Format = ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
			ans.R_AAAA_IP = [8]uint16{
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex : r.R_dataStartIndex+2]),
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex+2 : r.R_dataStartIndex+4]),
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex+4 : r.R_dataStartIndex+6]),
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex+6 : r.R_dataStartIndex+8]),
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex+8 : r.R_dataStartIndex+10]),
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex+10 : r.R_dataStartIndex+12]),
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex+12 : r.R_dataStartIndex+14]),
				util.ByteToUint16(p.OriginData[r.R_dataStartIndex+14 : r.R_dataStartIndex+16]),
			}
		}
	default:

	}
	return ans, nil
}

// return
// @ans PacketRecords
// @endIndex int
// @err error
func (p *PacketParser) parsePacketRecords(startIndex int) (PacketRecords, int, error) {
	data := &p.OriginData
	var i int
	var err error
	var r PacketRecords
	r.R_Name, i, err = p.parseName(startIndex)
	if err != nil {
		return PacketRecords{}, i, err
	}

	if i+10 > len((*data)) {
		return PacketRecords{}, i, fmt.Errorf(constant.ERROR_PACKET_RECORDS_TOO_SHORT)
	}

	r.R_Type = RecordType(util.ByteToUint16((*data)[i : i+2]))
	r.R_Class = ClassType(util.ByteToUint16((*data)[i+2 : i+4]))
	r.R_TimeToLive = util.ByteToUint32((*data)[i+4 : i+8])
	r.R_DataLength = util.ByteToUint16((*data)[i+8 : i+10])
	if r.R_DataLength != 0 {
		if i+10+int(r.R_DataLength) > len((*data)) {
			return PacketRecords{}, i + 10, fmt.Errorf(constant.ERROR_PACKET_RECORDS_TOO_SHORT)
		}
		// r.R_Data.R_originData = (*data)[i+10 : i+10+int(r.R_DataLength)]
		r.R_dataStartIndex = i + 10
		r.R_Data, err = p.parsePacketRecordData(&r)
		if err != nil {
			return r, i + 10, err
		}
	}
	return r, i + 10 + int(r.R_DataLength), nil
}

func (p *PacketParser) Parse() error {
	if len(p.OriginData) < 12 {
		return fmt.Errorf(constant.ERROR_MESSAGE_TOO_SHORT)
	}
	var err error
	p.Result.P_Header, err = p.parsePacketHeader(p.OriginData[0:12])
	if err != nil {
		return err
	}

	var i int = 12
	var q PacketQueries
	for j := 0; j < int(p.Result.P_Header.H_QueriesCount); j++ {
		q, i, err = p.parsePacketQueries(i)
		if err != nil {
			return err
		}
		p.Result.P_Queries = append(p.Result.P_Queries, q)
	}

	var r PacketRecords
	for j := 0; j < int(p.Result.P_Header.H_AnswerRRs); j++ {
		r, i, err = p.parsePacketRecords(i)
		if err != nil {
			return err
		}
		p.Result.P_Answers = append(p.Result.P_Answers, r)
	}

	for j := 0; j < int(p.Result.P_Header.H_AuthorityRRs); j++ {
		r, i, err = p.parsePacketRecords(i)
		if err != nil {
			return err
		}
		p.Result.P_Authority = append(p.Result.P_Authority, r)
	}

	for j := 0; j < int(p.Result.P_Header.H_AdditionalRRs); j++ {
		r, i, err = p.parsePacketRecords(i)
		if err != nil {
			return err
		}
		p.Result.P_Additional = append(p.Result.P_Additional, r)
	}

	return nil
}
