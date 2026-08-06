// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/icmp.mbt

///|
pub(all) struct IcmpHeader {
  icmp_type : Byte
  code : Byte
  checksum : UInt
  rest_of_header : UInt
  payload : Bytes
  is_checksum_valid : Bool
} derive(Eq, Debug)

///|
pub fn parse_icmp(data : Bytes) -> IcmpHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(8) {
    return None
  }
  let icmp_type = reader.read_u8()
  let code = reader.read_u8()
  let checksum = reader.read_u16()
  let rest_of_header = reader.read_u32()

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)
  let is_checksum_valid = @binary.verify_internet_checksum(
    data,
    0,
    data.length(),
  )

  Some({ icmp_type, code, checksum, rest_of_header, payload, is_checksum_valid })
}
