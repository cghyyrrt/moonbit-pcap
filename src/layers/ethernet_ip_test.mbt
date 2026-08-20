///|
test "ethernet ip register session frame" {
  let data = Bytes::from_array([
    b'\x65', b'\x00', // RegisterSession
     b'\x04', b'\x00', // payload length
     b'\x78', b'\x56', b'\x34', b'\x12', // session
     b'\x00', b'\x00', b'\x00', b'\x00', // status
     b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', // context
     b'\x00', b'\x00', b'\x00', b'\x00', // options
     b'\x01', b'\x00', b'\x00', b'\x00', // protocol version/options
  ])
  let parsed = parse_ethernet_ip(data)
  assert_true(parsed is Some(_))
  let frame = parsed.unwrap()
  assert_true(frame.command is RegisterSession)
  inspect(frame.length, content="4")
  inspect(frame.session_handle, content="305419896")
  inspect(frame.payload.length(), content="4")
}

///|
test "ethernet ip rejects truncation and declared overflow" {
  let short = Bytes::from_array(Array::make(23, b'\x00'))
  assert_true(parse_ethernet_ip(short) is None)
  let overflow = Bytes::from_array([
    b'\x00', b'\x00', b'\x20', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x00',
  ])
  assert_true(parse_ethernet_ip(overflow) is None)
}

///|
test "ethernet ip preserves unknown commands" {
  let data = Bytes::from_array([
    b'\x34', b'\x12', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
    b'\x00', b'\x00', b'\x00', b'\x00', b'\x00', b'\x00',
  ])
  let parsed = parse_ethernet_ip(data).unwrap()
  assert_true(parsed.command is Unknown(_))
}
