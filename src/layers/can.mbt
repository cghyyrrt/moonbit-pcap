// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/can.mbt

///|
pub(all) struct CanFrame {
  can_id : UInt
  is_extended : Bool
  is_rtr : Bool
  is_error : Bool
  dlc : Byte
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_socketcan(data : Bytes) -> CanFrame? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(8) {
    return None
  }
  let id_flags = reader.read_u32()
  let dlc = reader.read_u8()
  let _pad1 = reader.read_u8()
  let _res0 = reader.read_u8()
  let _res1 = reader.read_u8()

  let is_extended = ((id_flags >> 31) & 0x01U) != 0U
  let is_rtr = ((id_flags >> 30) & 0x01U) != 0U
  let is_error = ((id_flags >> 29) & 0x01U) != 0U

  let can_id = if is_extended {
    id_flags & 0x1FFFFFFF_U
  } else {
    id_flags & 0x000007FF_U
  }

  let dlc_int = dlc.to_int()
  let payload = if reader.has_bytes(dlc_int) {
    reader.read_bytes(dlc_int)
  } else {
    reader.read_bytes(reader.remaining())
  }

  Some({ can_id, is_extended, is_rtr, is_error, dlc, payload })
}
