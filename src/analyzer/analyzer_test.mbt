// Unit tests for src/analyzer module

///|
test "traffic statistics recording" {
  let stats = TrafficStats::new()
  stats.record_packet(64, "ETH")
  stats.record_packet(128, "IPv4")
  stats.record_packet(1024, "TCP")

  inspect(stats.get_total_packets(), content="3")
  inspect(stats.get_total_bytes(), content="1216")
  inspect(stats.get_min_len(), content="64")
  inspect(stats.get_max_len(), content="1024")

  let dist = stats.get_protocol_distribution()
  inspect(dist.eth_count, content="1")
  inspect(dist.ip4_count, content="1")
  inspect(dist.tcp_count, content="1")
}

///|
test "rtt tracking & estimation" {
  let tracker = RttTracker::new()
  let key = @reassembly.SessionKey::new("1.1.1.1", 100U, "2.2.2.2", 200U)
  tracker.record_handshake(key, 10.0, 10.050) // 50ms delta

  inspect(tracker.get_measurements().length(), content="1")
  let avg = tracker.get_avg_rtt()
  assert_true(avg > 49.0 && avg < 51.0)
}

///|
test "anomaly detection checksum check" {
  let detector = AnomalyDetector::new()
  detector.check_checksum(false, "IPv4", 1, 100.0)

  let anomalies = detector.get_anomalies()
  inspect(anomalies.length(), content="1")
  inspect(anomalies[0].kind, content="ChecksumMismatch")
}
