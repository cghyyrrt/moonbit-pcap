// Unit tests for UDP flow tracking and IP fragment reassembly

///|
test "udp flow tracking" {
  let tracker = UdpFlowTracker::new()
  let key = SessionKey::new(
    "192.168.1.100",
    5353U,
    "224.0.0.251",
    5353U,
    protocol=b'\x11',
  )

  tracker.record_packet(key, 120, 100.0)
  tracker.record_packet(key, 180, 101.5)

  let flows = tracker.get_flows()
  inspect(flows.length(), content="1")
  inspect(flows[0].packet_count, content="2")
  inspect(flows[0].total_bytes, content="300")
}

///|
test "ip fragment reassembly" {
  let reassembler = IpFragmentReassembler::new(1234U)
  let frag1 : IpFragment = {
    identification: 1234U,
    fragment_offset: 0U,
    more_fragments: true,
    data: Bytes::from_array([b'P', b'a', b'r', b't', b'1']),
  }
  let frag2 : IpFragment = {
    identification: 1234U,
    fragment_offset: 5U,
    more_fragments: false,
    data: Bytes::from_array([b'P', b'a', b'r', b't', b'2']),
  }

  reassembler.add_fragment(frag1)
  reassembler.add_fragment(frag2)

  let payload = reassembler.reassemble()
  assert_true(payload is Some(_))
  inspect(payload.unwrap().length(), content="10")
}
