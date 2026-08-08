// Unit tests for src/exporter module

///|
test "json export formatting" {
  let stats = @analyzer.TrafficStats::new()
  stats.record_packet(64, "ETH")
  stats.record_packet(512, "TCP")

  let json_str = export_stats_json(stats)
  assert_true(json_str.length() > 0)
}

///|
test "csv export formatting" {
  let writer = @pcap.PcapWriter::new()
  writer.write_packet(Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04']))
  let pcap_bytes = writer.to_bytes()
  let reader = @pcap.PcapReader::new(pcap_bytes).unwrap()
  let pkts = reader.read_all()

  let csv_str = export_packets_csv(pkts)
  assert_true(csv_str.length() > 0)
}

///|
test "terminal summary formatting" {
  let stats = @analyzer.TrafficStats::new()
  stats.record_packet(100, "IPv4")
  let anomalies = Array::new()

  let text_summary = export_terminal_summary(stats, anomalies)
  assert_true(text_summary.length() > 0)
}

///|
test "html report formatting" {
  let stats = @analyzer.TrafficStats::new()
  stats.record_packet(150, "TCP")
  let anomalies = Array::new()

  let html_str = export_html_report(stats, anomalies)
  assert_true(html_str.length() > 0)
}
