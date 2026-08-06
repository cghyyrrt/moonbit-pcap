// Unit tests for src/pcapng module

///|
test "pcapng writer and reader roundtrip" {
  let writer = PcapngWriter::new(endian=@binary.LittleEndian)
  let pkt1 = Bytes::from_array([b'\xDE', b'\xAD', b'\xBE', b'\xEF'])
  let pkt2 = Bytes::from_array([b'\x11', b'\x22', b'\x33', b'\x44', b'\x55'])

  writer.write_enhanced_packet(pkt1, ts_sec=100U, ts_usec=200U)
  writer.write_enhanced_packet(pkt2, ts_sec=101U, ts_usec=300U)

  let ng_bytes = writer.to_bytes()
  let reader = PcapngReader::new(ng_bytes)
  let packets = reader.read_all_packets()

  inspect(packets.length(), content="2")
  inspect(packets[0].cap_len, content="4")
  inspect(packets[1].cap_len, content="5")
}
