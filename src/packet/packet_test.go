package packet_test

import (
	"CyberLighthouse/packet"
	"fmt"
	"os"
	"testing"
)

var parserTestBinFile []string = []string{
	"/../../bin/parse_test/response-MX-google.com.bin",
	"/../../bin/parse_test/response-NS-google.com.bin",
	"/../../bin/parse_test/response-AAAA-ns1.google.com.bin",
	"/../../bin/parse_test/response-AAAAtoSOA.bin",
	"/../../bin/parse_test/response-CNAME-office.com-many.bin",
	"/../../bin/parse_test/response-CNAME-qq.com-many.bin",
}

// go test -v
func TestParser(t *testing.T) {
	for _, f := range parserTestBinFile {
		dir, err := os.Getwd()
		f = dir + f
		file, err := os.Open(f)
		if err != nil {
			t.Error(err, fmt.Sprintf("Read file %s failed.", f))
			continue
		}
		defer file.Close()

		buff := make([]byte, 1024)
		file.Read(buff)
		var pk packet.PacketParser
		pk.OriginData = buff
		err = pk.Parse()
		if err != nil {
			t.Error(err, "Parse failed.")
		} else {
			err = pk.Output()
			if err != nil {
				t.Error(err, "Output failed.")
			}
		}
	}
}
