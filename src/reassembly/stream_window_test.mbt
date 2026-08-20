///|
test "stream window drains out of order segments" {
  let window = SegmentWindow::new(initial_sequence=100U, max_buffer=32)
  assert_true(window.push(105U, Bytes::from_array([b'f', b'g'])))
  assert_true(
    window.push(100U, Bytes::from_array([b'a', b'b', b'c', b'd', b'e'])),
  )
  let first = window.drain_contiguous()
  inspect(first, content="b\"abcdefg\"")
  inspect(window.next_sequence(), content="107")
  inspect(window.buffered_bytes(), content="0")
}

///|
test "stream window rejects duplicates, gaps beyond capacity, and empty data" {
  let window = SegmentWindow::new(initial_sequence=0U, max_buffer=4)
  assert_true(!window.push(0U, Bytes::from_array([])))
  assert_true(window.push(0U, Bytes::from_array([b'a', b'b'])))
  assert_true(!window.push(0U, Bytes::from_array([b'a', b'b'])))
  assert_true(!window.push(10U, Bytes::from_array([b'x'])))
  inspect(window.dropped_segments(), content="3")
}

///|
test "stream window reports gaps and buffered sequences" {
  let window = SegmentWindow::new(initial_sequence=10U, max_buffer=20)
  assert_true(window.push(15U, Bytes::from_array([b'x', b'y'])))
  assert_true(window.contains_sequence(15U))
  inspect(window.oldest_pending_sequence().unwrap(), content="15")
  inspect(window.gap_size(), content="5")
  inspect(window.contiguous_length(), content="0")
}

///|
test "stream window exposes capacity and can accept checks" {
  let window = SegmentWindow::new(initial_sequence=10U, max_buffer=8)
  inspect(window.capacity(), content="8")
  assert_true(window.can_accept(10U, 4))
  assert_true(window.push(10U, Bytes::from_array([b'a', b'b'])))
  assert_true(!window.can_accept(10U, 1))
  assert_true(window.discard_before(12U) == 1)
  inspect(window.buffered_bytes(), content="0")
}
