// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcap/filter.mbt

///|
pub(all) struct PacketFilter {
  mut min_length : Int
  mut max_length : Int
  mut target_ip : String
  mut target_port : UInt
  mut protocol_name : String
} derive(Eq, Debug)

///|
pub fn PacketFilter::new() -> PacketFilter {
  {
    min_length: 0,
    max_length: 2147483647,
    target_ip: "",
    target_port: 0U,
    protocol_name: "",
  }
}

///|
pub fn PacketFilter::set_min_length(self : PacketFilter, min_len : Int) -> Unit {
  self.min_length = min_len
}

///|
pub fn PacketFilter::set_max_length(self : PacketFilter, max_len : Int) -> Unit {
  self.max_length = max_len
}

///|
pub fn PacketFilter::set_target_ip(self : PacketFilter, ip : String) -> Unit {
  self.target_ip = ip
}

///|
pub fn PacketFilter::set_target_port(self : PacketFilter, port : UInt) -> Unit {
  self.target_port = port
}

///|
pub fn PacketFilter::set_protocol(self : PacketFilter, proto : String) -> Unit {
  self.protocol_name = proto
}

///|
pub fn PacketFilter::matches(self : PacketFilter, pkt : PcapPacket) -> Bool {
  let len = pkt.payload.length()
  if len < self.min_length || len > self.max_length {
    return false
  }
  true
}
