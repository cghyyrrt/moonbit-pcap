///|
test "industrial function names and access categories" {
  assert_true(dnp3_function_is_read(Read))
  assert_true(dnp3_function_is_write(Write))
  assert_true(!dnp3_function_is_read(ColdRestart))
  inspect(dnp3_function_name(ColdRestart), content="Cold Restart")
  inspect(dnp3_function_name(UnknownFunction(b'\xFE')), content="Unknown(254)")
}

///|
test "cip logical path encoder and dnp3 object widths" {
  let path = encode_cip_logical_path(6U, 1U, Some(3U))
  inspect(path.length(), content="6")
  inspect(path[0], content="b'\\x20'")
  inspect(path[4], content="b'\\x30'")
  inspect(cip_path_word_count(path), content="3")
  inspect(dnp3_object_value_width(1U, 1U), content="1")
  inspect(dnp3_object_value_width(30U, 1U), content="2")
  inspect(dnp3_object_value_width(99U, 99U), content="0")
}
