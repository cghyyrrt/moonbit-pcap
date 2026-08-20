///|
test "cip request path and service parsing" {
  let data = Bytes::from_array([
    b'\x03', b'\x03', // GetAttributeSingle, path is 3 words
     b'\x20', b'\x06', // class 6
     b'\x24', b'\x01', // instance 1
     b'\x30', b'\x03', // attribute 3
     b'\xAA', b'\xBB',
  ])
  let message = parse_cip(data).unwrap()
  assert_true(message.service is GetAttributeSingle)
  assert_true(message.class_id == Some(6U))
  assert_true(message.instance_id == Some(1U))
  assert_true(message.attribute_id == Some(3U))
  inspect(message.data.length(), content="2")
}

///|
test "cip rejects path truncation and preserves response bit" {
  assert_true(parse_cip(Bytes::from_array([b'\x04'])) is None)
  let response = parse_cip(
    Bytes::from_array([b'\x8F', b'\x00', b'\x00', b'\x00']),
  ).unwrap()
  assert_true(response.is_response)
  assert_true(response.service is UnknownService(_))
}

///|
test "dnp3 binary and analog object values" {
  let binary = Bytes::from_array([b'\x01', b'\x80', b'\x02', b'\x00'])
  let values = parse_dnp3_binary_values(binary, 2).unwrap()
  inspect(values.length(), content="2")
  assert_true(values[0].value)
  inspect(values[1].index, content="3")

  let analog = Bytes::from_array([
    b'\x2A', b'\x00', b'\x00', b'\x00', b'\xFE', b'\xFF', b'\x03', b'\x00',
  ])
  let analog_values = parse_dnp3_analog_values(analog, 4).unwrap()
  inspect(analog_values[0].value, content="42")
  inspect(analog_values[1].value, content="-2")
}

///|
test "industrial object decoders reject partial values" {
  assert_true(parse_dnp3_binary_values(Bytes::from_array([b'\x01']), 0) is None)
  assert_true(
    parse_dnp3_analog_values(Bytes::from_array([b'\x01', b'\x00']), 0) is None,
  )
}
