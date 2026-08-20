///|
test "byte queue supports streaming append and consume" {
  let queue = ByteQueue::new()
  queue.push_bytes(Bytes::from_array([b'a', b'b']))
  queue.push(b'c')
  inspect(queue.length(), content="3")
  inspect(queue.peek().unwrap(), content="b'\\x61'")
  inspect(queue.take(2).unwrap(), content="b\"ab\"")
  inspect(queue.length(), content="1")
  inspect(queue.take_all(), content="b\"c\"")
  assert_true(queue.is_empty())
}

///|
test "byte queue handles invalid operations" {
  let queue = ByteQueue::new()
  assert_true(queue.peek() is None)
  assert_true(queue.take(1) is None)
  queue.push(b'x')
  assert_true(queue.take(-1) is None)
  inspect(queue.length(), content="1")
  queue.clear()
  assert_true(queue.is_empty())
}

///|
test "byte queue finds and consumes delimiters" {
  let queue = ByteQueue::new()
  queue.push_bytes(Bytes::from_array([b'a', b'=', b'1', b'\n', b'b']))
  assert_true(queue.find(Bytes::from_array([b'='])) == Some(1))
  let line = queue.take_through(Bytes::from_array([b'\n'])).unwrap()
  inspect(line.length(), content="4")
  assert_true(line[3] == b'\n')
  inspect(queue.get(0).unwrap(), content="b'\\x62'")
}
