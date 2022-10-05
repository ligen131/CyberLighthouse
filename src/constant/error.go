package constant

const (
	ERROR_MESSAGE_TOO_SHORT               string = "dns message too short"
	ERROR_PACKET_HEADER_FLAG_TOO_SHORT    string = "header flags too short"
	ERROR_PACKET_HEADER_TOO_SHORT         string = "header too short"
	ERROR_NAME_LENGTH_WRONG               string = "name length wrong"
	ERROR_NAME_NOT_END_BY_ZERO            string = "name not end by zero"
	ERROR_NAME_POINTER_WRONG              string = "name pointer error"
	ERROR_PACKET_QUERIES_TOO_SHORT        string = "queries too short"
	ERROR_PACKET_RECORDS_TOO_SHORT        string = "records too short"
	ERROR_PACKET_RECORD_DATA_LENGTH_WRONG string = "record's data length is wrong"
	ERROR_PACKET_HEADER_OPCODE_TOO_LARGE  string = "header Opcode too large"
	ERROR_PACKET_HEADER_RCODE_TOO_LARGE   string = "header Rcode too large"
	ERROR_PACKET_QUERIES_ARRAY_TOO_SHORT  string = "queries array too short"
	ERROR_PACKET_RECORDS_ARRAY_TOO_SHORT  string = "records array too short"
)
