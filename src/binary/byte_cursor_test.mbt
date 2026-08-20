///|
test "byte cursor reads bounded values and supports marks" {
  let cursor = ByteCursor::new(
    Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04', b'\x05']),
  )
  inspect(cursor.read_u16_le().unwrap(), content="513")
  let mark = cursor.mark()
  inspect(cursor.peek_u8().unwrap(), content="b'\\x03'")
  inspect(cursor.read_u8().unwrap(), content="b'\\x03'")
  cursor.reset(mark)
  inspect(cursor.position(), content="2")
  inspect(cursor.read_u24_be().unwrap(), content="197637")
  assert_true(cursor.at_end())
}

///|
test "byte cursor rejects partial reads without moving" {
  let cursor = ByteCursor::new(Bytes::from_array([b'\x01']))
  assert_true(cursor.read_u16_be() is None)
  inspect(cursor.position(), content="0")
  assert_true(cursor.take(2) is None)
  inspect(cursor.remaining(), content="1")
  assert_true(cursor.skip(1))
  assert_true(cursor.at_end())
}

///|
test "byte cursor reads wide integers and varuint" {
  let cursor = ByteCursor::new(
    Bytes::from_array([
      b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08', b'\xAC',
      b'\x02',
    ]),
  )
  inspect(cursor.read_u64_le().unwrap(), content="578437695752307201")
  inspect(cursor.read_varuint().unwrap(), content="300")
  assert_true(cursor.at_end())
}
