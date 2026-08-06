// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/udp.mbt

///|
pub(all) struct UdpHeader {
  src_port : UInt
  dst_port : UInt
  length : UInt
  checksum : UInt
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_udp(data : Bytes) -> UdpHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(8) {
    return None
  }
  let src_port = reader.read_u16()
  let dst_port = reader.read_u16()
  let length = reader.read_u16()
  let checksum = reader.read_u16()

  let len_int = length.reinterpret_as_int()
  let payload_len = if len_int >= 8 { len_int - 8 } else { reader.remaining() }

  let payload = if reader.has_bytes(payload_len) {
    reader.read_bytes(payload_len)
  } else {
    reader.read_bytes(reader.remaining())
  }

  Some({ src_port, dst_port, length, checksum, payload })
}
