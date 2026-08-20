///|
test "pcapng option builders preserve padding metadata" {
  let option = make_pcapng_option(2U, Bytes::from_array([b'a', b'b', b'c']))
  inspect(option.length, content="3")
  inspect(pcapng_option_padding(option), content="1")
  assert_true(!is_pcapng_end_option(option))
  let end = make_pcapng_end_option()
  assert_true(is_pcapng_end_option(end))
  inspect(end.value.length(), content="0")
}

///|
test "pcapng option text and empty values" {
  let option = make_pcapng_text_option(4U, "eth0")
  assert_true(option_value_as_text(option) == Some("eth0"))
  assert_true(
    option_value_as_text(make_pcapng_option(5U, Bytes::from_array([b'\xFF'])))
    is Some(_),
  )
  assert_true(
    option_value_as_text(make_pcapng_option(5U, Bytes::from_array([]))) ==
    Some(""),
  )
}
