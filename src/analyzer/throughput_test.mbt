// Unit tests for bandwidth tracking & throughput aggregation

///|
test "bandwidth tracker top conversations" {
  let tracker = BandwidthTracker::new()
  tracker.record_packet("192.168.1.1", "10.0.0.1", 1500)
  tracker.record_packet("10.0.0.1", "192.168.1.1", 2000)
  tracker.record_packet("192.168.1.2", "10.0.0.2", 500)

  let top = tracker.get_top_conversations(1)
  inspect(top.length(), content="1")
  inspect(top[0].total_bytes, content="3500")
}

///|
test "throughput aggregator time buckets" {
  let agg = ThroughputAggregator::new()
  agg.record_packet(1700000000, 1000)
  agg.record_packet(1700000000, 2000)
  agg.record_packet(1700000001, 500)

  let buckets = agg.get_buckets()
  inspect(buckets.length(), content="2")
  inspect(agg.get_peak_throughput(), content="3000")
}
