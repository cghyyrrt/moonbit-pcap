///|
test "traffic report tracks rates and percentiles" {
  let report = TrafficReport::new()
  report.record("TCP", 100, 1.0)
  report.record("TCP", 300, 2.0)
  report.record("UDP", 50, 4.0)
  inspect(report.packet_count(), content="3")
  inspect(report.byte_count(), content="450")
  inspect(report.duration(), content="3")
  inspect(report.average_packet_size(), content="150")
  inspect(report.protocol_count("TCP"), content="2")
  inspect(report.percentile_size(50), content="100")
  inspect(report.percentile_size(100), content="300")
}

///|
test "traffic report handles empty and invalid percentile inputs" {
  let report = TrafficReport::new()
  inspect(report.duration(), content="0")
  inspect(report.average_packet_size(), content="0")
  inspect(report.percentile_size(50), content="0")
  report.record("", -10, 4.0)
  inspect(report.packet_count(), content="1")
  inspect(report.byte_count(), content="0")
}

///|
test "protocol classification covers common ethertypes and ip protocols" {
  assert_true(classify_ethertype(0x0800U) is IPv4)
  assert_true(classify_ethertype(0x86DDU) is IPv6)
  assert_true(classify_ethertype(0x88CCU) is LinkLayerDiscovery)
  assert_true(classify_ip_protocol(b'\x06') is TCP)
  assert_true(classify_ip_protocol(b'\x11') is UDP)
  assert_true(classify_ip_protocol(b'\xFD') is UnknownProtocol(_))
}
