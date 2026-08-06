// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: analyzer/statistics.mbt

///|
pub(all) struct PacketLengthHistogram {
  mut bucket_0_64 : Int
  mut bucket_65_128 : Int
  mut bucket_129_512 : Int
  mut bucket_513_1024 : Int
  mut bucket_1025_1500 : Int
  mut bucket_jumbo : Int
} derive(Eq, Debug)

///|
pub(all) struct ProtocolDistribution {
  mut eth_count : Int
  mut arp_count : Int
  mut ip4_count : Int
  mut ip6_count : Int
  mut icmp_count : Int
  mut tcp_count : Int
  mut udp_count : Int
  mut dns_count : Int
  mut can_count : Int
  mut modbus_count : Int
  mut mqtt_count : Int
} derive(Eq, Debug)

///|
pub struct TrafficStats {
  mut total_packets : Int
  mut total_bytes : Int64
  mut min_len : Int
  mut max_len : Int
  proto_dist : ProtocolDistribution
  len_hist : PacketLengthHistogram
} derive(Eq, Debug)

///|
pub fn TrafficStats::new() -> TrafficStats {
  {
    total_packets: 0,
    total_bytes: 0L,
    min_len: 2147483647,
    max_len: 0,
    proto_dist: {
      eth_count: 0,
      arp_count: 0,
      ip4_count: 0,
      ip6_count: 0,
      icmp_count: 0,
      tcp_count: 0,
      udp_count: 0,
      dns_count: 0,
      can_count: 0,
      modbus_count: 0,
      mqtt_count: 0,
    },
    len_hist: {
      bucket_0_64: 0,
      bucket_65_128: 0,
      bucket_129_512: 0,
      bucket_513_1024: 0,
      bucket_1025_1500: 0,
      bucket_jumbo: 0,
    },
  }
}

///|
pub fn TrafficStats::record_packet(
  self : TrafficStats,
  len : Int,
  proto : String,
) -> Unit {
  self.total_packets = self.total_packets + 1
  self.total_bytes = self.total_bytes + len.to_int64()

  if len < self.min_len {
    self.min_len = len
  }
  if len > self.max_len {
    self.max_len = len
  }

  // Length histogram binning
  if len <= 64 {
    self.len_hist.bucket_0_64 = self.len_hist.bucket_0_64 + 1
  } else if len <= 128 {
    self.len_hist.bucket_65_128 = self.len_hist.bucket_65_128 + 1
  } else if len <= 512 {
    self.len_hist.bucket_129_512 = self.len_hist.bucket_129_512 + 1
  } else if len <= 1024 {
    self.len_hist.bucket_513_1024 = self.len_hist.bucket_513_1024 + 1
  } else if len <= 1500 {
    self.len_hist.bucket_1025_1500 = self.len_hist.bucket_1025_1500 + 1
  } else {
    self.len_hist.bucket_jumbo = self.len_hist.bucket_jumbo + 1
  }

  // Protocol distribution counter
  match proto {
    "ETH" => self.proto_dist.eth_count = self.proto_dist.eth_count + 1
    "ARP" => self.proto_dist.arp_count = self.proto_dist.arp_count + 1
    "IPv4" => self.proto_dist.ip4_count = self.proto_dist.ip4_count + 1
    "IPv6" => self.proto_dist.ip6_count = self.proto_dist.ip6_count + 1
    "ICMP" => self.proto_dist.icmp_count = self.proto_dist.icmp_count + 1
    "TCP" => self.proto_dist.tcp_count = self.proto_dist.tcp_count + 1
    "UDP" => self.proto_dist.udp_count = self.proto_dist.udp_count + 1
    "DNS" => self.proto_dist.dns_count = self.proto_dist.dns_count + 1
    "CAN" => self.proto_dist.can_count = self.proto_dist.can_count + 1
    "MODBUS" => self.proto_dist.modbus_count = self.proto_dist.modbus_count + 1
    "MQTT" => self.proto_dist.mqtt_count = self.proto_dist.mqtt_count + 1
    _ => ()
  }
}

///|
pub fn TrafficStats::get_avg_length(self : TrafficStats) -> Double {
  if self.total_packets == 0 {
    0.0
  } else {
    self.total_bytes.to_double() / self.total_packets.to_double()
  }
}

///|
pub fn TrafficStats::get_total_packets(self : TrafficStats) -> Int {
  self.total_packets
}

///|
pub fn TrafficStats::get_total_bytes(self : TrafficStats) -> Int64 {
  self.total_bytes
}

///|
pub fn TrafficStats::get_min_len(self : TrafficStats) -> Int {
  if self.min_len == 2147483647 {
    0
  } else {
    self.min_len
  }
}

///|
pub fn TrafficStats::get_max_len(self : TrafficStats) -> Int {
  self.max_len
}

///|
pub fn TrafficStats::get_protocol_distribution(
  self : TrafficStats,
) -> ProtocolDistribution {
  self.proto_dist
}

///|
pub fn TrafficStats::get_length_histogram(
  self : TrafficStats,
) -> PacketLengthHistogram {
  self.len_hist
}
