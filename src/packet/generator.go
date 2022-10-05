package packet

import (
	"CyberLighthouse/constant"
	"CyberLighthouse/util"
	"fmt"
)

type PacketGenerator struct {
	Pkt    Packet
	Result []byte
} // Didn't check is larger than 512 bytes and didn't use pointer

func (g *PacketGenerator) genPacketHeader() ([]byte, error) {
	ans := []byte{}
	req := bool(g.Pkt.P_Header.H_Flags.F_QR)
	a, b := util.Uint16ToByte(g.Pkt.P_Header.H_TransactionID)
	ans = append(ans, a, b)

	a = 0
	b = 0
	if req {
		a |= byte(1 << 7)
	}
	if g.Pkt.P_Header.H_Flags.F_Opcode > OpcodeType((1<<4)-1) {
		return append(ans, a), fmt.Errorf(constant.ERROR_PACKET_HEADER_OPCODE_TOO_LARGE)
	}
	a |= byte(g.Pkt.P_Header.H_Flags.F_Opcode << 3)
	if req && g.Pkt.P_Header.H_Flags.F_AA {
		a |= byte(1 << 2)
	}
	if g.Pkt.P_Header.H_Flags.F_TC {
		a |= byte(1 << 1)
	}
	if g.Pkt.P_Header.H_Flags.F_RD {
		a |= byte(1 << 0)
	}
	if req && g.Pkt.P_Header.H_Flags.F_RA {
		b |= byte(1 << 7)
	}
	if g.Pkt.P_Header.H_Flags.F_Z {
		b |= byte(1 << 6)
	}
	if g.Pkt.P_Header.H_Flags.F_AD {
		b |= byte(1 << 5)
	}
	if g.Pkt.P_Header.H_Flags.F_CD {
		b |= byte(1 << 4)
	}
	if g.Pkt.P_Header.H_Flags.F_rcode > RcodeType((1<<4)-1) {
		return append(ans, a, b), fmt.Errorf(constant.ERROR_PACKET_HEADER_RCODE_TOO_LARGE)
	}
	if req {
		b |= byte(g.Pkt.P_Header.H_Flags.F_rcode)
	}
	ans = append(ans, a, b)

	a, b = util.Uint16ToByte(g.Pkt.P_Header.H_QueriesCount)
	ans = append(ans, a, b)
	a, b = util.Uint16ToByte(g.Pkt.P_Header.H_AnswerRRs)
	ans = append(ans, a, b)
	a, b = util.Uint16ToByte(g.Pkt.P_Header.H_AuthorityRRs)
	ans = append(ans, a, b)
	a, b = util.Uint16ToByte(g.Pkt.P_Header.H_AdditionalRRs)
	ans = append(ans, a, b)

	return ans, nil
}

func (g *PacketGenerator) genStringByte(s string) []byte {
	ans := []byte{0}
	if s == "<Root>" || s == "." {
		s = ""
	}
	if s == "" {
		return ans
	}
	if s[len(s)-1] != byte('.') {
		s += "."
	}
	ans = append(ans, []byte(s)...)
	length := 0
	lastCountIndex := 0
	for i := range ans {
		if ans[i] == byte('.') || i == 0 {
			ans[lastCountIndex] = byte(length)
			ans[i] = 0
			length = 0
			lastCountIndex = i
		} else {
			length++
		}
	}
	return ans
}

func (g *PacketGenerator) genPacketQueries() ([]byte, error) {
	ans := []byte{}
	a := byte(0)
	b := byte(0)
	if len(g.Pkt.P_Queries) < int(g.Pkt.P_Header.H_QueriesCount) {
		return ans, fmt.Errorf(constant.ERROR_PACKET_QUERIES_ARRAY_TOO_SHORT)
	}
	for i := 0; i < int(g.Pkt.P_Header.H_QueriesCount); i++ {
		ans = append(ans, g.genStringByte(g.Pkt.P_Queries[i].Q_Name)...)
		a, b = util.Uint16ToByte(uint16(g.Pkt.P_Queries[i].Q_Type))
		ans = append(ans, a, b)
		a, b = util.Uint16ToByte(uint16(g.Pkt.P_Queries[i].Q_Class))
		ans = append(ans, a, b)
	}
	return ans, nil
}

func (g *PacketGenerator) genPacketRecordData(r *PacketRecords) []byte {
	data := []byte{}
	switch r.R_Type {
	case RECORD_A:
		data = r.R_Data.R_A_IP[:]
	case RECORD_NS:
		data = g.genStringByte(r.R_Data.R_NS_Name)
	case RECORD_CNAME:
		data = g.genStringByte(r.R_Data.R_CNAME_Name)
	case RECORD_MX:
		{
			a, b := util.Uint16ToByte(r.R_Data.R_MX.D_Preference)
			data = append(data, a, b)
			data = append(data, g.genStringByte(r.R_Data.R_MX.D_Name)...)
		}
	case RECORD_AAAA:
		{
			for i := 0; i < 8; i++ {
				a, b := util.Uint16ToByte(r.R_Data.R_AAAA_IP[i])
				data = append(data, a, b)
			}
		}
	default:
		data = r.R_Data.R_originData
	}
	r.R_DataLength = uint16(len(data))
	r.R_Data.R_originData = data
	a, b := util.Uint16ToByte(r.R_DataLength)
	ans := []byte{a, b}
	ans = append(ans, data...)
	return ans
}

func (g *PacketGenerator) genPacketRecords(r *[]PacketRecords, cnt uint16) ([]byte, error) {
	ans := []byte{}
	a, b, c, d := byte(0), byte(0), byte(0), byte(0)
	if len(*r) < int(cnt) {
		return ans, fmt.Errorf(constant.ERROR_PACKET_RECORDS_ARRAY_TOO_SHORT)
	}
	for i := 0; i < int(cnt); i++ {
		ans = append(ans, g.genStringByte((*r)[i].R_Name)...)
		a, b = util.Uint16ToByte(uint16((*r)[i].R_Type))
		ans = append(ans, a, b)
		a, b = util.Uint16ToByte(uint16((*r)[i].R_Class))
		ans = append(ans, a, b)
		a, b, c, d = util.Uint32ToByte((*r)[i].R_TimeToLive)
		ans = append(ans, a, b, c, d)
		ans = append(ans, g.genPacketRecordData(&(*r)[i])...)
	}
	return ans, nil
}

func (g *PacketGenerator) Generator() error {
	g.Result = []byte{}
	tmp, err := g.genPacketHeader()
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	tmp, err = g.genPacketQueries()
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	tmp, err = g.genPacketRecords(&g.Pkt.P_Answers, g.Pkt.P_Header.H_AnswerRRs)
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	tmp, err = g.genPacketRecords(&g.Pkt.P_Authority, g.Pkt.P_Header.H_AuthorityRRs)
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	tmp, err = g.genPacketRecords(&g.Pkt.P_Additional, g.Pkt.P_Header.H_AdditionalRRs)
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	return nil
}
