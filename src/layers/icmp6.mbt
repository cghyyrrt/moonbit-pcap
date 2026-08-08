// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/icmp6.mbt

///|
pub(all) struct Icmp6Header {
  icmp_type : Byte
  code : Byte
  checksum : UInt
  type_name : String
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn get_icmp6_type_name(t : Byte) -> String {
  match t {
    b'\x01' => "Destination Unreachable"
    b'\x02' => "Packet Too Big"
    b'\x03' => "Time Exceeded"
    b'\x04' => "Parameter Problem"
    b'\x80' => "Echo Request"
    b'\x81' => "Echo Reply"
    b'\x85' => "Router Solicitation"
    b'\x86' => "Router Advertisement"
    b'\x87' => "Neighbor Solicitation"
    b'\x88' => "Neighbor Advertisement"
    b'\x89' => "Redirect Message"
    _ => "Unknown ICMPv6 Type"
  }
}

///|
pub fn parse_icmp6(data : Bytes) -> Icmp6Header? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(4) {
    return None
  }
  let icmp_type = reader.read_u8()
  let code = reader.read_u8()
  let checksum = reader.read_u16()

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)
  let type_name = get_icmp6_type_name(icmp_type)

  Some({ icmp_type, code, checksum, type_name, payload })
}
