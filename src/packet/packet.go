package packet

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
	f_QR     bool       // 1 bit
	f_Opcode OpcodeType // 4 bits
	f_AA     bool       // 1 bit, req only
	f_TC     bool       // 1 bit
	f_RD     bool       // 1 bit
	// 1 byte
	f_RA    bool      // 1 bit, req only
	f_Z     bool      // 1 bit, should be 0
	f_AD    bool      // 1 bit, Answer authenticated: Answer/authority portion was not authenticated by the server
	f_CD    bool      // 1 bit, Non-authenticated data: Unacceptable
	f_rcode RcodeType // 4 bits, req only
} // 16 bits = 2 bytes totally, all codes are origin bytes

type PacketHeader struct {
	h_TransactionID uint16            // 2 bytes
	h_Flags         PacketHeaderFlags // 2 bytes
	h_QueriesCount  uint16            // 2 bytes
	h_AnswerRRs     uint16            // 2 bytes
	h_AuthorityRRs  uint16            // 2 bytes
	h_AdditionalRRs uint16            // 2 bytes
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
	q_Name  string     // End by 00
	q_Type  RecordType // 2 bytes
	q_Class ClassType  // 2 bytes, 1 Internet
} // [Name] + 4 bytes totally

type PacketRecords struct {
	r_Name           string     // End by 00, notice pointer
	r_Type           RecordType // 2 bytes
	r_Class          ClassType  // 2 bytes
	r_TimeToLive     uint32     // 4 bytes, TTL
	r_DataLength     uint16     // 2 bytes
	r_dataStartIndex int        // not exists in the record
	// r_Data           []byte
} // [Name] + 10 bytes + [Data] totally

type Packet struct {
	p_Header     PacketHeader
	p_Queries    []PacketQueries
	p_Answers    []PacketRecords
	p_Authority  []PacketRecords
	p_Additional []PacketRecords
}
