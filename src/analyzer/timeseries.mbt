// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: analyzer/timeseries.mbt

///|
pub(all) struct TimeBucket {
  timestamp_sec : Int
  mut packet_count : Int
  mut byte_count : Int64
} derive(Eq, Debug)

///|
pub struct ThroughputAggregator {
  buckets : Array[TimeBucket]
}

///|
pub fn ThroughputAggregator::new() -> ThroughputAggregator {
  { buckets: Array::new() }
}

///|
pub fn ThroughputAggregator::record_packet(
  self : ThroughputAggregator,
  timestamp_sec : Int,
  bytes_len : Int,
) -> Unit {
  let mut found = false
  for b in self.buckets {
    if b.timestamp_sec == timestamp_sec {
      b.packet_count = b.packet_count + 1
      b.byte_count = b.byte_count + bytes_len.to_int64()
      found = true
      break
    }
  }

  if !found {
    self.buckets.push({
      timestamp_sec,
      packet_count: 1,
      byte_count: bytes_len.to_int64(),
    })
  }
}

///|
pub fn ThroughputAggregator::get_peak_throughput(
  self : ThroughputAggregator,
) -> Int64 {
  let mut max_bytes = 0L
  for b in self.buckets {
    if b.byte_count > max_bytes {
      max_bytes = b.byte_count
    }
  }
  max_bytes
}

///|
pub fn ThroughputAggregator::get_buckets(
  self : ThroughputAggregator,
) -> Array[TimeBucket] {
  self.buckets
}
