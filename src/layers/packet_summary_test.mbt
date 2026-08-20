///|
test "packet summary classifies ethernet ipv4 tcp" {
  let packet = Bytes::from_array([
    b'\x00', b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08',
    b'\x09', b'\x0A', b'\x0B', b'\x08', b'\x00', b'\x45', b'\x00', b'\x00', b'\x28',
    b'\x00', b'\x01', b'\x00', b'\x00', b'\x40', b'\x06', b'\x00', b'\x00', b'\x0A',
    b'\x00', b'\x00', b'\x01', b'\x0A', b'\x00', b'\x00', b'\x02', b'\x12', b'\x34',
    b'\x00', b'\x50', b'\x00', b'\x00', b'\x00', b'\x01', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x50', b'\x02', b'\x20', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00',
  ])
  let summary = summarize_packet(packet).unwrap()
  inspect(summary.link, content="Ethernet")
  inspect(summary.network, content="IPv4")
  inspect(summary.transport, content="TCP")
  inspect(summary.src_port, content="4660")
  inspect(summary.dst_port, content="80")
}

///|
test "packet summary reports unknown and truncated payloads" {
  assert_true(summarize_packet(Bytes::from_array([])) is None)
  let packet = Bytes::from_array(Array::make(14, b'\x00'))
  let summary = summarize_packet(packet).unwrap()
  assert_true(summary.network == "Unknown")
  assert_true(summary.malformed)
}
