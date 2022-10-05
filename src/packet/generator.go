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
	req := bool(g.Pkt.p_Header.h_Flags.f_QR)
	a, b := util.Uint16ToByte(g.Pkt.p_Header.h_TransactionID)
	ans = append(ans, a, b)

	a = 0
	b = 0
	if req {
		a |= byte(1 << 7)
	}
	if g.Pkt.p_Header.h_Flags.f_Opcode > OpcodeType((1<<4)-1) {
		return append(ans, a), fmt.Errorf(constant.ERROR_PACKET_HEADER_OPCODE_TOO_LARGE)
	}
	a |= byte(g.Pkt.p_Header.h_Flags.f_Opcode << 3)
	if req && g.Pkt.p_Header.h_Flags.f_AA {
		a |= byte(1 << 2)
	}
	if g.Pkt.p_Header.h_Flags.f_TC {
		a |= byte(1 << 1)
	}
	if g.Pkt.p_Header.h_Flags.f_RD {
		a |= byte(1 << 0)
	}
	if req && g.Pkt.p_Header.h_Flags.f_RA {
		b |= byte(1 << 7)
	}
	if g.Pkt.p_Header.h_Flags.f_Z {
		b |= byte(1 << 6)
	}
	if g.Pkt.p_Header.h_Flags.f_AD {
		b |= byte(1 << 5)
	}
	if g.Pkt.p_Header.h_Flags.f_CD {
		b |= byte(1 << 4)
	}
	if g.Pkt.p_Header.h_Flags.f_rcode > RcodeType((1<<4)-1) {
		return append(ans, a, b), fmt.Errorf(constant.ERROR_PACKET_HEADER_RCODE_TOO_LARGE)
	}
	if req {
		b |= byte(g.Pkt.p_Header.h_Flags.f_rcode)
	}
	ans = append(ans, a, b)

	a, b = util.Uint16ToByte(g.Pkt.p_Header.h_QueriesCount)
	ans = append(ans, a, b)
	a, b = util.Uint16ToByte(g.Pkt.p_Header.h_AnswerRRs)
	ans = append(ans, a, b)
	a, b = util.Uint16ToByte(g.Pkt.p_Header.h_AuthorityRRs)
	ans = append(ans, a, b)
	a, b = util.Uint16ToByte(g.Pkt.p_Header.h_AdditionalRRs)
	ans = append(ans, a, b)

	return ans, nil
}

func (g *PacketGenerator) genStringByte(s string) []byte {
	ans := []byte{0}
	if s == "<Root>" {
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
	if len(g.Pkt.p_Queries) < int(g.Pkt.p_Header.h_QueriesCount) {
		return ans, fmt.Errorf(constant.ERROR_PACKET_QUERIES_ARRAY_TOO_SHORT)
	}
	for i := 0; i < int(g.Pkt.p_Header.h_QueriesCount); i++ {
		ans = append(ans, g.genStringByte(g.Pkt.p_Queries[i].q_Name)...)
		a, b = util.Uint16ToByte(uint16(g.Pkt.p_Queries[i].q_Type))
		ans = append(ans, a, b)
		a, b = util.Uint16ToByte(uint16(g.Pkt.p_Queries[i].q_Class))
		ans = append(ans, a, b)
	}
	return ans, nil
}

func (g *PacketGenerator) genPacketRecordData(r *PacketRecords) []byte {
	data := []byte{}
	switch r.r_Type {
	case RECORD_A:
		data = r.r_Data.r_A_IP[:]
	case RECORD_NS:
		data = g.genStringByte(r.r_Data.r_NS_Name)
	case RECORD_CNAME:
		data = g.genStringByte(r.r_Data.r_CNAME_Name)
	case RECORD_MX:
		{
			a, b := util.Uint16ToByte(r.r_Data.r_MX.d_Preference)
			data = append(data, a, b)
			data = append(data, g.genStringByte(r.r_Data.r_MX.d_Name)...)
		}
	case RECORD_AAAA:
		{
			for i := 0; i < 8; i++ {
				a, b := util.Uint16ToByte(r.r_Data.r_AAAA_IP[i])
				data = append(data, a, b)
			}
		}
	default:
		data = r.r_Data.r_originData
	}
	r.r_DataLength = uint16(len(data))
	r.r_Data.r_originData = data
	a, b := util.Uint16ToByte(r.r_DataLength)
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
		ans = append(ans, g.genStringByte((*r)[i].r_Name)...)
		a, b = util.Uint16ToByte(uint16((*r)[i].r_Type))
		ans = append(ans, a, b)
		a, b = util.Uint16ToByte(uint16((*r)[i].r_Class))
		ans = append(ans, a, b)
		a, b, c, d = util.Uint32ToByte((*r)[i].r_TimeToLive)
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

	tmp, err = g.genPacketRecords(&g.Pkt.p_Answers, g.Pkt.p_Header.h_AnswerRRs)
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	tmp, err = g.genPacketRecords(&g.Pkt.p_Authority, g.Pkt.p_Header.h_AuthorityRRs)
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	tmp, err = g.genPacketRecords(&g.Pkt.p_Additional, g.Pkt.p_Header.h_AdditionalRRs)
	if err != nil {
		return err
	}
	g.Result = append(g.Result, tmp...)

	return nil
}
