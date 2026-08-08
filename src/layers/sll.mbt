// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/sll.mbt

///|
pub(all) struct SllHeader {
  packet_type : UInt // 0 = unicast to us, 1 = broadcast, etc.
  arphrd_type : UInt
  address_length : UInt
  address : Bytes
  protocol : UInt
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_sll(data : Bytes) -> SllHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(16) {
    return None
  }
  let packet_type = reader.read_u16()
  let arphrd_type = reader.read_u16()
  let address_length = reader.read_u16()
  let address = reader.read_bytes(8)
  let protocol = reader.read_u16()

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)

  Some({ packet_type, arphrd_type, address_length, address, protocol, payload })
}
