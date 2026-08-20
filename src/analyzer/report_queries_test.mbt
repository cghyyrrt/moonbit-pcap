///|
test "report snapshot exposes stable totals" {
  let stats = TrafficStats::new()
  stats.record_packet(100, "TCP")
  stats.record_packet(200, "UDP")
  let snapshot = snapshot_stats(stats)
  inspect(snapshot.packets, content="2")
  inspect(snapshot.bytes, content="300")
  inspect(snapshot.average_size, content="150")
  inspect(throughput_mib_per_second(300L, 2.0), content="0.0001430511474609375")
}

///|
test "anomaly queries group severity and detect risk" {
  let anomalies : Array[NetworkAnomaly] = [
    {
      kind: "a",
      severity: High,
      description: "x",
      packet_idx: 1,
      timestamp: 1.0,
    },
    {
      kind: "b",
      severity: Critical,
      description: "y",
      packet_idx: 2,
      timestamp: 2.0,
    },
    {
      kind: "c",
      severity: Low,
      description: "z",
      packet_idx: 3,
      timestamp: 3.0,
    },
  ]
  let counts = summarize_anomalies(anomalies)
  inspect(counts.high_or_critical, content="2")
  inspect(counts.low_or_medium, content="1")
  assert_true(has_critical_anomaly(anomalies))
  assert_true(!has_critical_anomaly([anomalies[0]]))
}

///|
test "rate helpers handle zero and negative duration" {
  inspect(throughput_mib_per_second(1000L, 0.0), content="0")
  inspect(throughput_mib_per_second(1000L, -1.0), content="0")
  inspect(throughput_mib_per_second(-1L, 1.0), content="0")
}
