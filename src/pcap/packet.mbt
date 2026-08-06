// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcap/packet.mbt

///|
pub(all) struct PcapPacketHeader {
  ts_sec : UInt
  ts_usec : UInt
  incl_len : UInt
  orig_len : UInt
} derive(Eq, Debug)

///|
pub(all) struct PcapPacket {
  header : PcapPacketHeader
  payload : Bytes
  timestamp : Double
} derive(Eq, Debug)

///|
pub fn parse_packet_header(
  reader : @binary.BinaryReader,
  is_nanosecond : Bool,
) -> PcapPacketHeader? {
  if !reader.has_bytes(16) {
    return None
  }
  let ts_sec = reader.read_u32()
  let ts_usec = reader.read_u32()
  let incl_len = reader.read_u32()
  let orig_len = reader.read_u32()

  let _ = is_nanosecond
  Some({ ts_sec, ts_usec, incl_len, orig_len })
}

///|
pub fn calculate_timestamp(
  ts_sec : UInt,
  ts_usec : UInt,
  is_nanosecond : Bool,
) -> Double {
  let sec = ts_sec.reinterpret_as_int().to_double()
  let frac = ts_usec.reinterpret_as_int().to_double()
  if is_nanosecond {
    sec + frac / 1000000000.0
  } else {
    sec + frac / 1000000.0
  }
}
