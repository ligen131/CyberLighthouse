package packet_test

import (
	"CyberLighthouse/packet"
	"fmt"
	"os"
	"reflect"
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
		dir, _ := os.Getwd()
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
		var s string
		if err != nil {
			t.Error(err, "Parse failed.")
		} else {
			s, err = pk.Output()
			if err != nil {
				t.Error(err, "Output failed.")
			}
			fmt.Println(s)
		}
	}
}

func TestGenerator(t *testing.T) {
	for _, f := range parserTestBinFile {
		dir, _ := os.Getwd()
		f = dir + f
		file, err := os.Open(f)
		if err != nil {
			t.Error(err, fmt.Sprintf("Read file %s failed.", f))
			continue
		}
		defer file.Close()

		buff := make([]byte, 1024)
		n, _ := file.Read(buff)
		var pk packet.PacketParser
		pk.OriginData = buff
		err = pk.Parse()
		if err != nil {
			t.Error(err, "Parse failed.")
		}

		var ge packet.PacketGenerator
		ge.Pkt = pk.Result
		err = ge.Generator()
		if err != nil {
			t.Error(err, "Generate failed.")
		}
		var pk2 packet.PacketParser
		pk2.OriginData = ge.Result
		err = pk2.Parse()
		if err != nil {
			t.Error(err, "Parse2 failed.")
		}
		fmt.Println("------------------------------------------------")
		var s1, s2 string
		s1, err = pk.Output()
		if err != nil {
			t.Error(err, "Output failed.")
		}
		s2, err = pk2.Output()
		if err != nil {
			t.Error(err, "Output2 failed.")
		}
		fmt.Println(s1)
		fmt.Println(s2)
		fmt.Println("------------------------------------------------")
		if reflect.DeepEqual(pk.Result, pk2.Result) || s1 != s2 {
			t.Error(err, "Generate check failed. Result not the same.\n", buff[:n], "\n", ge.Result)
		}
	}
}
