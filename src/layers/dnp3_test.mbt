///|
test "dnp3 parses valid link and transport headers" {
  let data = Bytes::from_array([
    b'\x05', b'\x64', b'\x0B', b'\xC4', // start, length, control
     b'\x01', b'\x00', b'\x02', b'\x00', // destination, source
     b'\x00', b'\x00', // header CRC placeholder for fixture
     b'\xC0', b'\x01', // transport, application
     b'\x01', b'\x01', b'\x00', b'\x00', // object header group/variation/qualifier/count
  ])
  let parsed = parse_dnp3(data)
  assert_true(parsed is Some(_))
  let frame = parsed.unwrap()
  inspect(frame.link.destination, content="1")
  inspect(frame.link.source, content="2")
  inspect(frame.transport.sequence, content="b'\\x00'")
  inspect(frame.application.sequence, content="b'\\x01'")
  inspect(frame.objects.length(), content="1")
}

///|
test "dnp3 rejects malformed framing" {
  assert_true(parse_dnp3(Bytes::from_array([])) is None)
  assert_true(
    parse_dnp3(Bytes::from_array([b'\x05', b'\x63', b'\x05', b'\x00'])) is None,
  )
  let truncated = Bytes::from_array([
    b'\x05', b'\x64', b'\x0B', b'\xC4', b'\x01', b'\x00', b'\x02', b'\x00',
  ])
  assert_true(parse_dnp3(truncated) is None)
}

///|
test "dnp3 exposes unknown object headers without panicking" {
  let data = Bytes::from_array([
    b'\x05', b'\x64', b'\x0B', b'\xC4', b'\x01', b'\x00', b'\x02', b'\x00', b'\x00',
    b'\x00', b'\xC0', b'\x01', b'\xFE', b'\xFF', b'\x00', b'\x01',
  ])
  let frame = parse_dnp3(data).unwrap()
  inspect(frame.objects[0].group, content="b'\\xFE'")
  inspect(frame.objects[0].variation, content="b'\\xFF'")
}
