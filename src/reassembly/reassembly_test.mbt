// Unit tests for src/reassembly module

///|
test "5-tuple canonicalization" {
  let key1 = SessionKey::new("192.168.1.1", 80U, "192.168.1.2", 443U)
  let key2 = SessionKey::new("192.168.1.2", 443U, "192.168.1.1", 80U)

  let c1 = key1.canonical()
  let c2 = key2.canonical()

  inspect(c1 == c2, content="true")
}

///|
test "tcp out-of-order reassembly" {
  let key = SessionKey::new("10.0.0.1", 12345U, "10.0.0.2", 80U)
  let reassembler = TcpStreamReassembler::new(key)
  reassembler.set_initial_seq(1000U)

  let seg1_data = Bytes::from_array([b'H', b'e', b'l', b'l', b'o'])
  let seg2_data = Bytes::from_array([b' ', b'W', b'o', b'r', b'l', b'd'])

  // Add seg2 first (out of order seq=1005), then seg1 (seq=1000)
  reassembler.add_segment(1005U, seg2_data, 1.1)
  reassembler.add_segment(1000U, seg1_data, 1.0)

  let final_bytes = reassembler.get_data()
  let str_buf = StringBuilder::new()
  for i = 0; i < final_bytes.length(); i = i + 1 {
    str_buf.write_char(final_bytes[i].to_int().unsafe_to_char())
  }

  inspect(str_buf.to_string(), content="Hello World")
}
