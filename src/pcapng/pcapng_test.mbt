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

///|
test "name resolver map lookup" {
  let resolver = NameResolver::new()
  let rec : NameRecord = {
    record_type: 1U,
    ip_address: Bytes::from_array([b'\xC0', b'\xA8', b'\x01', b'\x01']),
    hostnames: ["router.local"],
  }
  resolver.add_record(rec)

  let hostname = resolver.resolve_ip4("192.168.1.1")
  assert_true(hostname is Some(_))
  inspect(hostname.unwrap(), content="router.local")
}
