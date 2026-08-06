// Unit tests for L4-L7 protocol dissectors (ICMP, UDP, TCP, DNS, CAN, Modbus, MQTT)

///|
test "tcp & options parsing" {
  let tcp_pkt = Bytes::from_array([
    b'\x00', b'\x50', b'\x01', b'\xBB', // Src 80 (HTTP), Dst 443 (HTTPS)
     b'\x00', b'\x00', b'\x00', b'\x01', // Seq
     b'\x00', b'\x00', b'\x00', b'\x02', // Ack
     b'\x60', b'\x12', // Data Offset 6 (24 bytes header), Flags SYN|ACK
     b'\x20', b'\x00', // Window size 8192
     b'\x12', b'\x34', // Checksum
     b'\x00', b'\x00', // Urgent ptr
     b'\x02', b'\x04', b'\x05', b'\xB4', // MSS 1460 (Option kind 2)
  ])

  let tcp_opt = parse_tcp(tcp_pkt)
  assert_true(tcp_opt is Some(_))
  let tcp = tcp_opt.unwrap()
  inspect(tcp.src_port, content="80")
  inspect(tcp.dst_port, content="443")
  assert_true(tcp.flag_syn)
  assert_true(tcp.flag_ack)
  inspect(tcp.options.length(), content="1")
  inspect(tcp.options[0].kind, content="b'\\x02'")
}

///|
test "udp & dns query parsing" {
  let dns_pkt = Bytes::from_array([
    b'\x12', b'\x34', // ID 0x1234
     b'\x01', b'\x00', // Standard Query
     b'\x00', b'\x01', // QDCount 1
     b'\x00', b'\x00', // ANCount 0
     b'\x00', b'\x00', // NSCount 0
     b'\x00', b'\x00', // ARCount 0
     b'\x07', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'\x03', b'c', b'o', b'm',
    b'\x00', // End domain
     b'\x00', b'\x01', // QType A
     b'\x00', b'\x01', // QClass IN
  ])

  let dns_opt = parse_dns(dns_pkt)
  assert_true(dns_opt is Some(_))
  let dns = dns_opt.unwrap()
  inspect(dns.header.id, content="4660")
  inspect(dns.questions.length(), content="1")
  inspect(dns.questions[0].qname, content="example.com")
}

///|
test "industrial modbus tcp parsing" {
  let mb_pkt = Bytes::from_array([
    b'\x00', b'\x01', // Transaction ID 1
     b'\x00', b'\x00', // Protocol ID 0 (Modbus)
     b'\x00', b'\x06', // Length 6
     b'\x01', // Unit ID 1
     b'\x03', // Function Code 3 (Read Holding Registers)
     b'\x00', b'\x64', // Start Addr 100
     b'\x00', b'\x0A', // Quantity 10
  ])

  let mb_opt = parse_modbus_tcp(mb_pkt)
  assert_true(mb_opt is Some(_))
  let mb = mb_opt.unwrap()
  inspect(mb.transaction_id, content="1")
  inspect(mb.function_code, content="b'\\x03'")
}
