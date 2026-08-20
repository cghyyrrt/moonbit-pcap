// Deterministic traffic report helpers for applications and benchmark output.

///|
pub(all) enum ProtocolClass {
  IPv4
  IPv6
  ARP
  VLAN
  LinkLayerDiscovery
  EtherNetIP
  DNP3
  UnknownEtherType(UInt)
} derive(Eq, Debug)

///|
pub(all) enum TransportClass {
  ICMP
  TCP
  UDP
  SCTP
  GRE
  UnknownProtocol(Byte)
} derive(Eq, Debug)

///|
pub(all) struct TrafficSample {
  protocol : String
  bytes : Int
  timestamp : Double
} derive(Eq, Debug)

///|
pub struct TrafficReport {
  samples : Array[TrafficSample]
}

///|
/// Map an Ethernet type to a stable protocol class.
pub fn classify_ethertype(value : UInt) -> ProtocolClass {
  match value {
    0x0800U => IPv4
    0x0806U => ARP
    0x8100U | 0x88A8U => VLAN
    0x86DDU => IPv6
    0x88CCU => LinkLayerDiscovery
    _ => UnknownEtherType(value)
  }
}

///|
/// Identify common industrial services by their TCP/UDP port.
pub fn classify_service_port(port : UInt) -> ProtocolClass? {
  match port {
    44818U => Some(EtherNetIP)
    20000U => Some(DNP3)
    _ => None
  }
}

///|
/// Map an IP protocol number to a transport class.
pub fn classify_ip_protocol(value : Byte) -> TransportClass {
  match value {
    b'\x01' => ICMP
    b'\x06' => TCP
    b'\x11' => UDP
    b'\x2F' => GRE
    b'\x84' => SCTP
    _ => UnknownProtocol(value)
  }
}

///|
/// Construct an empty report.
pub fn TrafficReport::new() -> TrafficReport {
  { samples: [] }
}

///|
/// Record a packet sample; negative sizes are normalized to zero.
pub fn TrafficReport::record(
  self : TrafficReport,
  protocol : String,
  bytes : Int,
  timestamp : Double,
) -> Unit {
  let normalized = if bytes < 0 { 0 } else { bytes }
  self.samples.push({ protocol, bytes: normalized, timestamp })
}

///|
/// Number of samples recorded.
pub fn TrafficReport::packet_count(self : TrafficReport) -> Int {
  self.samples.length()
}

///|
/// Sum of normalized sample sizes.
pub fn TrafficReport::byte_count(self : TrafficReport) -> Int64 {
  let mut total = 0L
  for sample in self.samples {
    total = total + sample.bytes.to_int64()
  }
  total
}

///|
/// Elapsed time from first to last sample.
pub fn TrafficReport::duration(self : TrafficReport) -> Double {
  if self.samples.length() < 2 {
    0.0
  } else {
    let mut first = self.samples[0].timestamp
    let mut last = first
    for sample in self.samples {
      if sample.timestamp < first {
        first = sample.timestamp
      }
      if sample.timestamp > last {
        last = sample.timestamp
      }
    }
    last - first
  }
}

///|
/// Average packet size in bytes.
pub fn TrafficReport::average_packet_size(self : TrafficReport) -> Double {
  if self.packet_count() == 0 {
    0.0
  } else {
    self.byte_count().to_double() / self.packet_count().to_double()
  }
}

///|
/// Count samples for a protocol label.
pub fn TrafficReport::protocol_count(
  self : TrafficReport,
  protocol : String,
) -> Int {
  let mut count = 0
  for sample in self.samples {
    if sample.protocol == protocol {
      count = count + 1
    }
  }
  count
}

///|
fn sorted_sizes(samples : Array[TrafficSample]) -> Array[Int] {
  let sizes : Array[Int] = []
  for sample in samples {
    sizes.push(sample.bytes)
  }
  for i = 1; i < sizes.length(); i = i + 1 {
    let value = sizes[i]
    let mut j = i - 1
    while j >= 0 && sizes[j] > value {
      sizes[j + 1] = sizes[j]
      j = j - 1
    }
    sizes[j + 1] = value
  }
  sizes
}

///|
/// Return the nearest-rank packet size percentile, clamped to 0..100.
pub fn TrafficReport::percentile_size(
  self : TrafficReport,
  percentile : Int,
) -> Int {
  if self.samples.length() == 0 {
    return 0
  }
  let p = if percentile < 0 {
    0
  } else if percentile > 100 {
    100
  } else {
    percentile
  }
  let sizes = sorted_sizes(self.samples)
  let rank = if p == 0 { 0 } else { (p * sizes.length() + 99) / 100 - 1 }
  sizes[rank]
}

///|
/// Return a copy of the recorded samples for export.
pub fn TrafficReport::samples(self : TrafficReport) -> Array[TrafficSample] {
  self.samples
}
