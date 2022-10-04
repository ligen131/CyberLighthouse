package packet

type PacketGenerator struct {
	Pkt    Packet
	Result []byte
} // Didn't check is larger than 512 bytes and didn't use pointer

func (g *PacketGenerator) genPacketHeader() {

}

func (g *PacketGenerator) Generator() error {

	return nil
}
