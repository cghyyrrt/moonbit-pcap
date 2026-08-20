///|
test "pcapng validator accepts writer output" {
  let writer = PcapngWriter::new()
  writer.write_enhanced_packet(
    Bytes::from_array([b'a', b'b', b'c', b'd']),
    ts_sec=1U,
    ts_usec=2U,
  )
  let report = validate_pcapng(writer.to_bytes())
  assert_true(report.valid)
  inspect(report.block_count, content="3")
  inspect(report.packet_count, content="1")
  assert_true(report.issues.length() == 0)
}

///|
test "pcapng validator reports short and mismatched blocks" {
  let short = validate_pcapng(Bytes::from_array([b'\x0A', b'\x0D', b'\x0D']))
  assert_true(!short.valid)
  assert_true(short.issues[0] is TruncatedBlockHeader)

  let bad = Bytes::from_array([
    b'\x01', b'\x00', b'\x00', b'\x00', b'\x0C', b'\x00', b'\x00', b'\x00', b'\x08',
    b'\x00', b'\x00', b'\x00',
  ])
  let report = validate_pcapng(bad)
  assert_true(!report.valid)
  assert_true(report.issues[0] is InvalidTrailingLength)
}
