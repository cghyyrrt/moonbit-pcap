// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: analyzer/bandwidth.mbt

///|
pub(all) struct HostPairStats {
  host_a : String
  host_b : String
  mut total_packets : Int
  mut total_bytes : Int64
} derive(Eq, Debug)

///|
pub struct BandwidthTracker {
  pairs : Array[HostPairStats]
}

///|
pub fn BandwidthTracker::new() -> BandwidthTracker {
  { pairs: Array::new() }
}

///|
pub fn BandwidthTracker::record_packet(
  self : BandwidthTracker,
  src_ip : String,
  dst_ip : String,
  bytes_len : Int,
) -> Unit {
  let (h_a, h_b) = if src_ip < dst_ip {
    (src_ip, dst_ip)
  } else {
    (dst_ip, src_ip)
  }

  let mut found = false
  for pair in self.pairs {
    if pair.host_a == h_a && pair.host_b == h_b {
      pair.total_packets = pair.total_packets + 1
      pair.total_bytes = pair.total_bytes + bytes_len.to_int64()
      found = true
      break
    }
  }

  if !found {
    self.pairs.push({
      host_a: h_a,
      host_b: h_b,
      total_packets: 1,
      total_bytes: bytes_len.to_int64(),
    })
  }
}

///|
pub fn BandwidthTracker::get_top_conversations(
  self : BandwidthTracker,
  top_n : Int,
) -> Array[HostPairStats] {
  // Sort pairs by total_bytes descending
  let len = self.pairs.length()
  for i = 0; i < len; i = i + 1 {
    for j = i + 1; j < len; j = j + 1 {
      if self.pairs[i].total_bytes < self.pairs[j].total_bytes {
        let tmp = self.pairs[i]
        self.pairs[i] = self.pairs[j]
        self.pairs[j] = tmp
      }
    }
  }

  let res = Array::new()
  let count = if len < top_n { len } else { top_n }
  for i = 0; i < count; i = i + 1 {
    res.push(self.pairs[i])
  }
  res
}
