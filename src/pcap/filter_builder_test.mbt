///|
test "packet filter builder normalizes ranges" {
  let filter = PacketFilter::new()
  filter.set_min_length(-5)
  filter.set_max_length(100)
  filter.set_target_port(44818U)
  filter.set_protocol("tcp")
  assert_true(filter.is_valid())
  inspect(
    filter.describe(),
    content="length=0..100 protocol=tcp port=44818 ip=any",
  )
}

///|
test "packet filter matches packet length boundaries" {
  let filter = PacketFilter::new()
  filter.set_min_length(3)
  filter.set_max_length(4)
  let packet : PcapPacket = {
    header: { ts_sec: 0U, ts_usec: 0U, incl_len: 3U, orig_len: 3U },
    payload: Bytes::from_array([b'a', b'b', b'c']),
    timestamp: 0.0,
  }
  assert_true(filter.matches(packet))
  filter.set_min_length(4)
  assert_true(!filter.matches(packet))
}
