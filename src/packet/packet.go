package packet

import "fmt"

// Reference: http://c.biancheng.net/view/6457.html
// Reference: https://blog.csdn.net/answer3lin/article/details/84638845
// Document: https://www.rfc-editor.org/rfc/rfc1035#section-4.1.1

type OpcodeType uint8

const (
	OPCODE_STANDARD    OpcodeType = 0
	OPCODE_INVERSE     OpcodeType = 1
	OPCODE_STATUS      OpcodeType = 2
	OPCODE_UNSUPPORTED OpcodeType = 3
)

type RcodeType uint8

const (
	RCODE_NOERROR         RcodeType = 0
	RCODE_FORMAT_ERROR    RcodeType = 1
	RCODE_SERVER_FAILURE  RcodeType = 2
	RCODE_NAME_ERROR      RcodeType = 3
	RCODE_NOT_IMPLEMENTED RcodeType = 4
	RCODE_REFUSED         RcodeType = 5
	RCODE_OTHER_ERROR     RcodeType = 6
)

type PacketHeaderFlags struct {
	F_QR     bool       // 1 bit, query = 0, req = 1
	F_Opcode OpcodeType // 4 bits
	F_AA     bool       // 1 bit, req only
	F_TC     bool       // 1 bit
	F_RD     bool       // 1 bit
	// 1 byte
	F_RA    bool      // 1 bit, req only
	F_Z     bool      // 1 bit, should be 0
	F_AD    bool      // 1 bit, Answer authenticated: Answer/authority portion was not authenticated by the server
	F_CD    bool      // 1 bit, Non-authenticated data: Unacceptable
	F_rcode RcodeType // 4 bits, req only
} // 16 bits = 2 bytes totally, all codes are origin bytes

type PacketHeader struct {
	H_TransactionID uint16            // 2 bytes
	H_Flags         PacketHeaderFlags // 2 bytes
	H_QueriesCount  uint16            // 2 bytes
	H_AnswerRRs     uint16            // 2 bytes
	H_AuthorityRRs  uint16            // 2 bytes
	H_AdditionalRRs uint16            // 2 bytes
} // 12 bytes totally

type RecordType uint16

const (
	RECORD_A             RecordType = 1
	RECORD_NS            RecordType = 2
	RECORD_CNAME         RecordType = 5
	RECORD_MX            RecordType = 15
	RECORD_AAAA          RecordType = 28
	RECORD_NOT_SUPPORTED RecordType = 0
)

type ClassType uint16

const (
	CLASS_INTERNET ClassType = 1
	CLASS_CS       ClassType = 2
	CLASS_CH       ClassType = 3
	CLASS_HS       ClassType = 4
	CLASS_ANY      ClassType = 255
)

type PacketQueries struct {
	Q_Name  string     // End by 00
	Q_Type  RecordType // 2 bytes
	Q_Class ClassType  // 2 bytes, 1 Internet
} // [Name] + 4 bytes totally

type PacketRecordMXData struct {
	D_Preference uint16
	D_Name       string
}

type PacketRecordData struct {
	R_A_IP       [4]byte
	R_NS_Name    string
	R_CNAME_Name string
	R_MX         PacketRecordMXData
	R_AAAA_IP    [8]uint16
	R_originData []byte
} // Likes union

type PacketRecords struct {
	R_Name           string     // End by 00, notice pointer
	R_Type           RecordType // 2 bytes
	R_Class          ClassType  // 2 bytes
	R_TimeToLive     uint32     // 4 bytes, TTL
	R_DataLength     uint16     // 2 bytes
	R_dataStartIndex int        // not exists in the record
	R_Data           PacketRecordData
} // [Name] + 10 bytes + [Data] totally

type Packet struct {
	P_Header     PacketHeader
	P_Queries    []PacketQueries
	P_Answers    []PacketRecords
	P_Authority  []PacketRecords
	P_Additional []PacketRecords
}

func (p *Packet) outputRecordType(r RecordType, isShort bool) string {
	if !isShort {
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
	switch r {
	case RECORD_A:
		return "A"
	case RECORD_NS:
		return "NS"
	case RECORD_CNAME:
		return "CNAME"
	case RECORD_MX:
		return "MX"
	case RECORD_AAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("Unknow(%d)", int(r))
	}
}

func (p *Packet) outputClassType(c ClassType, isShort bool) string {
	if !isShort {
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
	switch c {
	case CLASS_INTERNET:
		return "IN"
	case CLASS_CS:
		return "CS"
	case CLASS_CH:
		return "CH"
	case CLASS_HS:
		return "HS"
	case CLASS_ANY:
		return "ANY"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", int(c))
	}
}

func (p *Packet) outputRecordData(r *PacketRecords, isShort bool) string {
	if !isShort {
		ans := ""
		switch r.R_Type {
		case RECORD_A:
			ans += fmt.Sprintf("Address: %d.%d.%d.%d", int(r.R_Data.R_A_IP[0]),
				int(r.R_Data.R_A_IP[1]), int(r.R_Data.R_A_IP[2]), int(r.R_Data.R_A_IP[3]))
		case RECORD_NS:
			ans += "Name Server: " + r.R_Data.R_NS_Name
		case RECORD_CNAME:
			ans += "CNAME: " + r.R_Data.R_CNAME_Name
		case RECORD_MX:
			ans += fmt.Sprintf("Mail Exchange: Preference: %d; ", r.R_Data.R_MX.D_Preference)
			ans += "Name: " + r.R_Data.R_MX.D_Name
		case RECORD_AAAA:
			ans += fmt.Sprintf("AAAA Address: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
				int(r.R_Data.R_AAAA_IP[0]), int(r.R_Data.R_AAAA_IP[1]),
				int(r.R_Data.R_AAAA_IP[2]), int(r.R_Data.R_AAAA_IP[3]),
				int(r.R_Data.R_AAAA_IP[4]), int(r.R_Data.R_AAAA_IP[5]),
				int(r.R_Data.R_AAAA_IP[6]), int(r.R_Data.R_AAAA_IP[7]))
		default:
			ans += fmt.Sprintf("Not supported record. data = %v", r.R_Data.R_originData)
		}
		return ans
	}
	switch r.R_Type {
	case RECORD_A:
		return fmt.Sprintf("%d.%d.%d.%d", int(r.R_Data.R_A_IP[0]),
			int(r.R_Data.R_A_IP[1]), int(r.R_Data.R_A_IP[2]), int(r.R_Data.R_A_IP[3]))
	case RECORD_NS:
		return r.R_Data.R_NS_Name
	case RECORD_CNAME:
		return r.R_Data.R_CNAME_Name
	case RECORD_MX:
		return fmt.Sprintf("%d\t%s", r.R_Data.R_MX.D_Preference, r.R_Data.R_MX.D_Name)
	case RECORD_AAAA:
		return fmt.Sprintf("%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
			int(r.R_Data.R_AAAA_IP[0]), int(r.R_Data.R_AAAA_IP[1]),
			int(r.R_Data.R_AAAA_IP[2]), int(r.R_Data.R_AAAA_IP[3]),
			int(r.R_Data.R_AAAA_IP[4]), int(r.R_Data.R_AAAA_IP[5]),
			int(r.R_Data.R_AAAA_IP[6]), int(r.R_Data.R_AAAA_IP[7]))
	default:
		return fmt.Sprintf("Not supported record. data = %v", r.R_Data.R_originData)
	}
}

func (p *Packet) outputQueries(q *PacketQueries, isShort bool) string {
	if !isShort {
		ans := ""
		ans += "			Name: " + q.Q_Name + "\n"
		ans += "			" + p.outputRecordType(q.Q_Type, isShort) + "\n"
		ans += "			" + p.outputClassType(q.Q_Class, isShort) + "\n"
		return ans
	}
	// Name	Class	Type
	return fmt.Sprintf("%s\t%s\t%s\n", q.Q_Name, p.outputClassType(q.Q_Class, isShort), p.outputRecordType(q.Q_Type, isShort))
}

func (p *Packet) outputRecords(r *PacketRecords, isShort bool) string {
	if !isShort {
		ans := ""
		ans += "			Name: " + r.R_Name + "\n"
		ans += "			" + p.outputRecordType(r.R_Type, isShort) + "\n"
		ans += "			" + p.outputClassType(r.R_Class, isShort) + "\n"
		ans += fmt.Sprintf("			Time to live: %d\n", r.R_TimeToLive)
		ans += fmt.Sprintf("			Data length: %d\n", r.R_DataLength)
		ans += "			" + p.outputRecordData(r, isShort) + "\n"
		return ans
	}
	// Name	Class	Type	TTL	Data
	return fmt.Sprintf("%s\t%s\t%s\t%d\t%s\n", r.R_Name, p.outputClassType(r.R_Class, isShort),
		p.outputRecordType(r.R_Type, isShort), r.R_TimeToLive, p.outputRecordData(r, isShort))
}

func (p *Packet) outputRcode(c RcodeType) string {
	ans := ""
	switch c {
	case RCODE_NOERROR:
		ans = "No error (0)"
	case RCODE_FORMAT_ERROR:
		ans = "Format error (1)"
	case RCODE_SERVER_FAILURE:
		ans = "Server failure (2)"
	case RCODE_NAME_ERROR:
		ans = "Name error (3)"
	case RCODE_NOT_IMPLEMENTED:
		ans = "Not implemented (4)"
	case RCODE_REFUSED:
		ans = "Refused (5)"
	default:
		ans = fmt.Sprintf("Other error (%d)", int(p.P_Header.H_Flags.F_rcode))
	}
	return ans
}

func (p *Packet) Output(isShort bool) string {
	if !isShort {
		ans := "Domain Name System "
		req := p.P_Header.H_Flags.F_QR
		if req {
			ans += "(response)\n"
		} else {
			ans += "(query)\n"
		}

		// ------------------ Header ------------------
		ans += fmt.Sprintf("	Transaction ID: 0x%x\n", p.P_Header.H_TransactionID)
		ans += "	Flags:\n"
		if req {
			ans += "		Response: Message is a response\n"
		} else {
			ans += "		Response: Message is a query\n"
		}
		switch p.P_Header.H_Flags.F_Opcode {
		case OPCODE_STANDARD:
			ans += "		Opcode: Standard query (0)\n"
		case OPCODE_INVERSE:
			ans += "		Opcode: Inverse query (1)\n"
		case OPCODE_STATUS:
			ans += "		Opcode: Status query (2)\n"
		default:
			ans += fmt.Sprintf("		Opcode: Not supported query (%d)\n", int(p.P_Header.H_Flags.F_Opcode))
		}
		if req {
			if p.P_Header.H_Flags.F_AA {
				ans += "		Authoritative: Server is an authority for domain\n"
			} else {
				ans += "		Authoritative: Server is not an authority for domain\n"
			}
		}
		if !p.P_Header.H_Flags.F_TC {
			ans += "		Truncated: Message is not truncated\n"
		} else {
			ans += "		Truncated: Message is truncated\n"
		}
		if p.P_Header.H_Flags.F_RD {
			ans += "		Recursion desired: Do query recursively\n"
		} else {
			ans += "		Recursion desired: Do not query recursively\n"
		}
		if req {
			if p.P_Header.H_Flags.F_RA {
				ans += "		Recursion available: Server can do recursive queries\n"
			} else {
				ans += "		Recursion unavailable: Server can not do recursive queries\n"
			}
		}
		if !p.P_Header.H_Flags.F_Z {
			ans += "		Z: reserved (0)\n"
		} else {
			ans += "		Z: reserved (1)\n"
		}
		if p.P_Header.H_Flags.F_AD {
			ans += "		AD bit: Set\n"
		} else {
			ans += "		Answer authenticated: Answer/authority portion was not authenticated by the server\n"
		}
		if p.P_Header.H_Flags.F_CD {
			ans += "		CD bit: Set\n"
		} else {
			ans += "		Non-authenticated data: Unacceptable\n"
		}
		if req {
			ans += "		Reply code: " + p.outputRcode(p.P_Header.H_Flags.F_rcode) + "\n"
		}

		ans += fmt.Sprintf("	Questions: %d\n", int(p.P_Header.H_QueriesCount))
		ans += fmt.Sprintf("	Answer RRs: %d\n", int(p.P_Header.H_AnswerRRs))
		ans += fmt.Sprintf("	Authority RRs: %d\n", int(p.P_Header.H_AuthorityRRs))
		ans += fmt.Sprintf("	Additional RRs: %d\n", int(p.P_Header.H_AdditionalRRs))
		// ------------------ Header End ------------------

		// ------------------ Queries ------------------
		if p.P_Header.H_QueriesCount > 0 {
			ans += "	Queries:\n"
			for i := range p.P_Queries {
				ans += fmt.Sprintf("		[%d] queries\n", i)
				ans += p.outputQueries(&p.P_Queries[i], isShort)
			}
		}
		// ------------------ Queries End ------------------

		// ------------------ Records ------------------
		if p.P_Header.H_AnswerRRs > 0 {
			ans += "	Answers:\n"
			for i := range p.P_Answers {
				ans += fmt.Sprintf("		[%d] answers\n", i)
				ans += p.outputRecords(&p.P_Answers[i], isShort)
			}
		}
		if p.P_Header.H_AuthorityRRs > 0 {
			ans += "	Authoritative nameservers:\n"
			for i := range p.P_Authority {
				ans += fmt.Sprintf("		[%d] authoritative nameservers\n", i)
				ans += p.outputRecords(&p.P_Authority[i], isShort)
			}
		}
		if p.P_Header.H_AdditionalRRs > 0 {
			ans += "	Additional records:\n"
			for i := range p.P_Additional {
				ans += fmt.Sprintf("		[%d] additional records\n", i)
				ans += p.outputRecords(&p.P_Additional[i], isShort)
			}
		}
		// ------------------ Records End ------------------

		return ans
	}

	ans := ";; Reply code: " + p.outputRcode(p.P_Header.H_Flags.F_rcode) + "\n"
	ans += fmt.Sprintf(";; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		p.P_Header.H_QueriesCount, p.P_Header.H_AnswerRRs, p.P_Header.H_AuthorityRRs, p.P_Header.H_AdditionalRRs)
	// ------------------ Queries ------------------
	if p.P_Header.H_QueriesCount > 0 {
		ans += "\n;; QUESTIONS SECTION:\n"
		for i := range p.P_Queries {
			ans += p.outputQueries(&p.P_Queries[i], isShort)
		}
	}
	// ------------------ Queries End ------------------

	// ------------------ Records ------------------
	if p.P_Header.H_AnswerRRs > 0 {
		ans += "\n;; ANSWERS SECTION:\n"
		for i := range p.P_Answers {
			ans += p.outputRecords(&p.P_Answers[i], isShort)
		}
	}
	if p.P_Header.H_AuthorityRRs > 0 {
		ans += "\n;; AUTHORITIES SECTION:\n"
		for i := range p.P_Authority {
			ans += p.outputRecords(&p.P_Authority[i], isShort)
		}
	}
	if p.P_Header.H_AdditionalRRs > 0 {
		ans += "\n;; ADDITIONAL SECTION:\n"
		for i := range p.P_Additional {
			ans += p.outputRecords(&p.P_Additional[i], isShort)
		}
	}
	// ------------------ Records End ------------------

	return ans
}
