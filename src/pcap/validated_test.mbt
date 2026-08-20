///|
test "pcap validator reports valid and truncated captures" {
  let writer = PcapWriter::new()
  writer.write_packet(
    Bytes::from_array([b'a', b'b', b'c']),
    ts_sec=10U,
    ts_usec=20U,
  )
  let report = validate_pcap(writer.to_bytes())
  assert_true(report.valid)
  inspect(report.packet_count, content="1")
  inspect(report.captured_bytes, content="3")
  assert_true(report.issues.length() == 0)

  let truncated = Bytes::from_array([b'\xD4', b'\xC3', b'\xB2', b'\xA1'])
  let invalid = validate_pcap(truncated)
  assert_true(!invalid.valid)
  assert_true(invalid.issues[0] is TruncatedGlobalHeader)
}

///|
test "pcap validator distinguishes packet header and payload truncation" {
  let writer = PcapWriter::new()
  writer.write_packet(Bytes::from_array([b'x', b'y', b'z']))
  let full = writer.to_bytes()
  let header_only = @binary.BinaryReader::new(full)
  let _ = parse_magic(header_only)
  let packet_header = header_only.read_bytes(16)
  let header_bytes : Array[Byte] = []
  for b in packet_header {
    header_bytes.push(b)
  }
  let report = validate_pcap(Bytes::from_array(header_bytes))
  assert_true(!report.valid)
  assert_true(report.issues[0] is TruncatedGlobalHeader)
}

///|
test "pcap validator rejects invalid magic" {
  let report = validate_pcap(Bytes::from_array(Array::make(24, b'\x00')))
  assert_true(!report.valid)
  assert_true(report.issues[0] is InvalidMagic)
}
