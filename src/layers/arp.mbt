// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/arp.mbt

///|
pub(all) struct ArpHeader {
  hardware_type : UInt
  protocol_type : UInt
  hardware_size : Byte
  protocol_size : Byte
  opcode : UInt
  sender_mac : Bytes
  sender_ip : Bytes
  target_mac : Bytes
  target_ip : Bytes
} derive(Eq, Debug)

///|
pub fn parse_arp(data : Bytes) -> ArpHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(8) {
    return None
  }
  let hardware_type = reader.read_u16()
  let protocol_type = reader.read_u16()
  let hardware_size = reader.read_u8()
  let protocol_size = reader.read_u8()
  let opcode = reader.read_u16()

  let h_len = hardware_size.to_int()
  let p_len = protocol_size.to_int()

  if !reader.has_bytes(h_len * 2 + p_len * 2) {
    return None
  }

  let sender_mac = reader.read_bytes(h_len)
  let sender_ip = reader.read_bytes(p_len)
  let target_mac = reader.read_bytes(h_len)
  let target_ip = reader.read_bytes(p_len)

  Some({
    hardware_type,
    protocol_type,
    hardware_size,
    protocol_size,
    opcode,
    sender_mac,
    sender_ip,
    target_mac,
    target_ip,
  })
}
