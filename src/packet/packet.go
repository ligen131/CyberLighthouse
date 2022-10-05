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
