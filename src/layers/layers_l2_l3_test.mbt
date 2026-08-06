// Unit tests for L2 and L3 protocol dissectors

///|
test "ethernet & vlan parsing" {
  let eth_pkt = Bytes::from_array([
    b'\x00', b'\x11', b'\x22', b'\x33', b'\x44', b'\x55', // Dst MAC
     b'\x66', b'\x77', b'\x88', b'\x99', b'\xAA', b'\xBB', // Src MAC
     b'\x81', b'\x00', b'\x00', b'\x64', // 802.1Q VLAN 100
     b'\x08', b'\x00', // EtherType IPv4
     b'\x45', b'\x00', b'\x00', b'\x14', // IPv4 payload start
  ])

  let eth_opt = parse_ethernet(eth_pkt)
  assert_true(eth_opt is Some(_))
  let eth = eth_opt.unwrap()
  inspect(eth.ethertype, content="2048") // 0x0800
  inspect(eth.vlan_tags.length(), content="1")
  inspect(eth.vlan_tags[0].vid, content="100")
}

///|
test "ipv4 header parsing & checksum" {
  let ip_pkt = Bytes::from_array([
    b'\x45', b'\x00', b'\x00', b'\x1C', b'\x1C', b'\x46', b'\x40', b'\x00', b'\x40',
    b'\x06', b'\xB5', b'\x1C', b'\xC0', b'\xA8', b'\x01', b'\x01', b'\xC0', b'\xA8',
    b'\x01', b'\x02', b'\x00', b'\x50', b'\x00', b'\x50', b'\x00', b'\x00', b'\x00',
    b'\x00',
  ])

  let ip_opt = parse_ipv4(ip_pkt)
  assert_true(ip_opt is Some(_))
  let ip = ip_opt.unwrap()
  inspect(ip.protocol, content="b'\\x06'")
  inspect(@binary.ip4_to_string(ip.src_ip), content="192.168.1.1")
  inspect(@binary.ip4_to_string(ip.dst_ip), content="192.168.1.2")
}
