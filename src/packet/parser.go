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
	flags.f_QR = bool((a & (1 << 7)) != 0)
	flags.f_Opcode = OpcodeType((a & 0b01111000) >> 3)
	flags.f_AA = bool((a & (1 << 2)) != 0)
	flags.f_TC = bool((a & (1 << 1)) != 0)
	flags.f_RD = bool((a & (1 << 0)) != 0)

	flags.f_RA = bool((b & (1 << 7)) != 0)
	flags.f_Z = bool((b & (1 << 6)) != 0)
	flags.f_AD = bool((b & (1 << 5)) != 0)
	flags.f_CD = bool((b & (1 << 4)) != 0)
	flags.f_rcode = RcodeType(b & 0b00001111)
	return flags, nil
}

func (p *PacketParser) parsePacketHeader(data []byte) (PacketHeader, error) {
	if len(data) != 12 {
		return PacketHeader{},
			fmt.Errorf(constant.ERROR_PACKET_HEADER_TOO_SHORT)
	}
	var header PacketHeader
	var err error
	header.h_TransactionID = util.ByteToUint16(data[0:2])

	header.h_Flags, err = p.parsePacketHeaderFlags(data[2:4])
	if err != nil {
		return PacketHeader{}, err
	}

	header.h_QueriesCount = util.ByteToUint16(data[4:6])
	header.h_AnswerRRs = util.ByteToUint16(data[6:8])
	header.h_AuthorityRRs = util.ByteToUint16(data[8:10])
	header.h_AdditionalRRs = util.ByteToUint16(data[10:12])
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
	for i = startIndex; i < len(*data); i++ {
		b := (*data)[i]
		if length == 0 {
			if i != startIndex {
				ans += "."
			}
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
			length = uint8(b)
		} else {
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
	q.q_Name, i, err = p.parseName(startIndex)
	if err != nil {
		return PacketQueries{}, i, err
	}
	if i+4 > len((*data)) {
		return PacketQueries{}, i, fmt.Errorf(constant.ERROR_PACKET_QUERIES_TOO_SHORT)
	}
	q.q_Type = RecordType(util.ByteToUint16((*data)[i : i+2]))
	q.q_Class = ClassType(util.ByteToUint16((*data)[i+2 : i+4]))
	return q, i + 4, nil
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
	r.r_Name, i, err = p.parseName(startIndex)
	if err != nil {
		return PacketRecords{}, i, err
	}

	if i+10 > len((*data)) {
		return PacketRecords{}, i, fmt.Errorf(constant.ERROR_PACKET_RECORDS_TOO_SHORT)
	}

	r.r_Type = RecordType(util.ByteToUint16((*data)[i : i+2]))
	r.r_Class = ClassType(util.ByteToUint16((*data)[i+2 : i+4]))
	r.r_TimeToLive = util.ByteToUint32((*data)[i+4 : i+8])
	r.r_DataLength = util.ByteToUint16((*data)[i+8 : i+10])
	if r.r_DataLength != 0 {
		if i+10+int(r.r_DataLength) > len((*data)) {
			return PacketRecords{}, i + 10, fmt.Errorf(constant.ERROR_PACKET_RECORDS_TOO_SHORT)
		}
		// r.r_Data = data[i+10 : i+10+int(r.r_DataLength)]
		r.r_dataStartIndex = i + 10
	}
	return r, i + 10 + int(r.r_DataLength), nil
}

func (p *PacketParser) Parse() error {
	if len(p.OriginData) < 12 {
		return fmt.Errorf(constant.ERROR_MESSAGE_TOO_SHORT)
	}
	var err error
	p.Result.p_Header, err = p.parsePacketHeader(p.OriginData[0:12])
	if err != nil {
		return err
	}

	var i int = 12
	var q PacketQueries
	for j := 0; j < int(p.Result.p_Header.h_QueriesCount); j++ {
		q, i, err = p.parsePacketQueries(i)
		if err != nil {
			return err
		}
		p.Result.p_Queries = append(p.Result.p_Queries, q)
	}

	var r PacketRecords
	for j := 0; j < int(p.Result.p_Header.h_AnswerRRs); j++ {
		r, i, err = p.parsePacketRecords(i)
		if err != nil {
			return err
		}
		p.Result.p_Answers = append(p.Result.p_Answers, r)
	}

	for j := 0; j < int(p.Result.p_Header.h_AuthorityRRs); j++ {
		r, i, err = p.parsePacketRecords(i)
		if err != nil {
			return err
		}
		p.Result.p_Authority = append(p.Result.p_Authority, r)
	}

	for j := 0; j < int(p.Result.p_Header.h_AdditionalRRs); j++ {
		r, i, err = p.parsePacketRecords(i)
		if err != nil {
			return err
		}
		p.Result.p_Additional = append(p.Result.p_Additional, r)
	}

	return nil
}

func (p *PacketParser) outputRecordType(r RecordType) string {
	ans := "Type: "
	switch r {
	case RECORD_A:
		ans += "A (1)"
	case RECORD_NS:
		ans += "NS (2)"
	case RECORD_CNAME:
		ans += "CNAME (5)"
	case RECORD_MX:
		ans += "MX (15)"
	case RECORD_AAAA:
		ans += "AAAA (28)"
	default:
		ans += fmt.Sprintf("Not supported record (%d)", int(r))
	}
	return ans
}

func (p *PacketParser) outputClassType(c ClassType) string {
	ans := "Class: "
	switch c {
	case CLASS_INTERNET:
		ans += "IN (0x0001)"
	case CLASS_CS:
		ans += "CS (0x0002)"
	case CLASS_CH:
		ans += "CH (0x0003)"
	case CLASS_HS:
		ans += "HS (0x0004)"
	case CLASS_ANY:
		ans += "ANY (0x00ff)"
	default:
		ans += fmt.Sprintf("Not supported class (0x%04x)", int(c))
	}
	return ans
}

func (p *PacketParser) outputRecordData(r *PacketRecords) (string, error) {
	ans := ""
	var err error
	var s string
	var i int
	switch r.r_Type {
	case RECORD_A:
		{
			// IPv4 Address. Format = 255.255.255.255
			ans += fmt.Sprintf("Address: %d.%d.%d.%d", int(p.OriginData[r.r_dataStartIndex]),
				int(p.OriginData[r.r_dataStartIndex+1]), int(p.OriginData[r.r_dataStartIndex+2]),
				int(p.OriginData[r.r_dataStartIndex+3]))
		}
	case RECORD_NS:
		{
			s, i, err = p.parseName(r.r_dataStartIndex)
			if err != nil {
				return ans, err
			}
			ans += "Name Server: " + s
			if i != r.r_dataStartIndex+int(r.r_DataLength) {
				return ans, fmt.Errorf(constant.ERROR_PACKET_RECORD_DATA_LENGTH_WRONG)
			}
		}
	case RECORD_CNAME:
		{
			s, i, err = p.parseName(r.r_dataStartIndex)
			if err != nil {
				return ans, err
			}
			ans += "CNAME: " + s
			if i != r.r_dataStartIndex+int(r.r_DataLength) {
				return ans, fmt.Errorf(constant.ERROR_PACKET_RECORD_DATA_LENGTH_WRONG)
			}
		}
	case RECORD_MX:
		{
			ans += fmt.Sprintf("Mail Exchange: Preference: %d; ",
				util.ByteToUint16(p.OriginData[r.r_dataStartIndex:r.r_dataStartIndex+2]))
			s, i, err = p.parseName(r.r_dataStartIndex + 2)
			if err != nil {
				return ans, err
			}
			ans += "Name: " + s
			if i != r.r_dataStartIndex+int(r.r_DataLength) {
				return ans, fmt.Errorf(constant.ERROR_PACKET_RECORD_DATA_LENGTH_WRONG)
			}
		}
	case RECORD_AAAA:
		{
			// IPv6 Address. Format = ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
			ans += fmt.Sprintf("AAAA Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
				int(p.OriginData[r.r_dataStartIndex]), int(p.OriginData[r.r_dataStartIndex+1]),
				int(p.OriginData[r.r_dataStartIndex+2]), int(p.OriginData[r.r_dataStartIndex+3]),
				int(p.OriginData[r.r_dataStartIndex+4]), int(p.OriginData[r.r_dataStartIndex+5]),
				int(p.OriginData[r.r_dataStartIndex+6]), int(p.OriginData[r.r_dataStartIndex+7]),
				int(p.OriginData[r.r_dataStartIndex+8]), int(p.OriginData[r.r_dataStartIndex+9]),
				int(p.OriginData[r.r_dataStartIndex+10]), int(p.OriginData[r.r_dataStartIndex+11]),
				int(p.OriginData[r.r_dataStartIndex+12]), int(p.OriginData[r.r_dataStartIndex+13]),
				int(p.OriginData[r.r_dataStartIndex+14]), int(p.OriginData[r.r_dataStartIndex+15]))
		}
	default:
		{
			ans += fmt.Sprintf("Not supported record. data = %v",
				p.OriginData[r.r_dataStartIndex:r.r_dataStartIndex+int(r.r_DataLength)])
		}
	}
	return ans, nil
}

func (p *PacketParser) outputQueries(q *PacketQueries) string {
	ans := ""
	ans += "			Name: " + q.q_Name + "\n"
	ans += "			" + p.outputRecordType(q.q_Type) + "\n"
	ans += "			" + p.outputClassType(q.q_Class) + "\n"
	return ans
}

func (p *PacketParser) outputRecords(r *PacketRecords) (string, error) {
	ans := ""
	ans += "			Name: " + r.r_Name + "\n"
	ans += "			" + p.outputRecordType(r.r_Type) + "\n"
	ans += "			" + p.outputClassType(r.r_Class) + "\n"
	ans += fmt.Sprintf("			Time to live: %d\n", r.r_TimeToLive)
	ans += fmt.Sprintf("			Data length: %d\n", r.r_DataLength)
	s, err := p.outputRecordData(r)
	if err != nil {
		return ans, err
	}
	ans += "			" + s + "\n"
	return ans, nil
}

func (p *PacketParser) Output() error {
	ans := "Domain Name System "
	req := p.Result.p_Header.h_Flags.f_QR
	if req {
		ans += "(response)\n"
	} else {
		ans += "(query)\n"
	}

	// ------------------ Header ------------------
	ans += fmt.Sprintf("	Transaction ID: 0x%x\n", p.Result.p_Header.h_TransactionID)
	ans += "	Flags:\n"
	if req {
		ans += "		Response: Message is a response\n"
	} else {
		ans += "		Response: Message is a query\n"
	}
	switch p.Result.p_Header.h_Flags.f_Opcode {
	case OPCODE_STANDARD:
		ans += "		Opcode: Standard query (0)\n"
	case OPCODE_INVERSE:
		ans += "		Opcode: Inverse query (1)\n"
	case OPCODE_STATUS:
		ans += "		Opcode: Status query (2)\n"
	default:
		ans += fmt.Sprintf("		Opcode: Not supported query (%d)\n", int(p.Result.p_Header.h_Flags.f_Opcode))
	}
	if req {
		if p.Result.p_Header.h_Flags.f_AA {
			ans += "		Authoritative: Server is an authority for domain\n"
		} else {
			ans += "		Authoritative: Server is not an authority for domain\n"
		}
	}
	if !p.Result.p_Header.h_Flags.f_TC {
		ans += "		Truncated: Message is not truncated\n"
	} else {
		ans += "		Truncated: Message is truncated\n"
	}
	if p.Result.p_Header.h_Flags.f_RD {
		ans += "		Recursion desired: Do query recursively\n"
	} else {
		ans += "		Recursion desired: Do not query recursively\n"
	}
	if req {
		if p.Result.p_Header.h_Flags.f_RA {
			ans += "		Recursion available: Server can do recursive queries\n"
		} else {
			ans += "		Recursion unavailable: Server can not do recursive queries\n"
		}
	}
	if !p.Result.p_Header.h_Flags.f_Z {
		ans += "		Z: reserved (0)\n"
	} else {
		ans += "		Z: reserved (1)\n"
	}
	if p.Result.p_Header.h_Flags.f_AD {
		ans += "		AD bit: Set\n"
	} else {
		ans += "		Answer authenticated: Answer/authority portion was not authenticated by the server\n"
	}
	if p.Result.p_Header.h_Flags.f_CD {
		ans += "		CD bit: Set\n"
	} else {
		ans += "		Non-authenticated data: Unacceptable\n"
	}
	if req {
		ans += "		Reply code: "
		switch p.Result.p_Header.h_Flags.f_rcode {
		case RCODE_NOERROR:
			ans += "No error (0)\n"
		case RCODE_FORMAT_ERROR:
			ans += "Format error (1)\n"
		case RCODE_SERVER_FAILURE:
			ans += "Server failure (2)\n"
		case RCODE_NAME_ERROR:
			ans += "Name error (3)\n"
		case RCODE_NOT_IMPLEMENTED:
			ans += "Not implemented (4)\n"
		case RCODE_REFUSED:
			ans += "Refused (5)\n"
		default:
			ans += fmt.Sprintf("Other error (%d)\n", int(p.Result.p_Header.h_Flags.f_rcode))
		}
	}
	ans += fmt.Sprintf("	Questions: %d\n", int(p.Result.p_Header.h_QueriesCount))
	ans += fmt.Sprintf("	Answer RRs: %d\n", int(p.Result.p_Header.h_AnswerRRs))
	ans += fmt.Sprintf("	Authority RRs: %d\n", int(p.Result.p_Header.h_AuthorityRRs))
	ans += fmt.Sprintf("	Additional RRs: %d\n", int(p.Result.p_Header.h_AdditionalRRs))
	// ------------------ Header End ------------------

	// ------------------ Queries ------------------
	if p.Result.p_Header.h_QueriesCount > 0 {
		ans += "	Queries:\n"
		for i := range p.Result.p_Queries {
			ans += fmt.Sprintf("		[%d] queries\n", i)
			ans += p.outputQueries(&p.Result.p_Queries[i])
		}
	}
	// ------------------ Queries End ------------------

	// ------------------ Records ------------------
	if p.Result.p_Header.h_AnswerRRs > 0 {
		ans += "	Answers:\n"
		for i := range p.Result.p_Answers {
			ans += fmt.Sprintf("		[%d] answers\n", i)
			s, err := p.outputRecords(&p.Result.p_Answers[i])
			if err != nil {
				return err
			}
			ans += s
		}
	}
	if p.Result.p_Header.h_AuthorityRRs > 0 {
		ans += "	Authoritative nameservers:\n"
		for i := range p.Result.p_Authority {
			ans += fmt.Sprintf("		[%d] authoritative nameservers\n", i)
			s, err := p.outputRecords(&p.Result.p_Authority[i])
			if err != nil {
				return err
			}
			ans += s
		}
	}
	if p.Result.p_Header.h_AdditionalRRs > 0 {
		ans += "	Additional records:\n"
		for i := range p.Result.p_Additional {
			ans += fmt.Sprintf("		[%d] additional records\n", i)
			s, err := p.outputRecords(&p.Result.p_Additional[i])
			if err != nil {
				return err
			}
			ans += s
		}
	}
	// ------------------ Records End ------------------

	fmt.Println(ans)
	return nil
}
