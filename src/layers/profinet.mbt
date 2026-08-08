// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/profinet.mbt

///|
pub(all) struct ProfinetHeader {
  frame_id : UInt
  cycle_counter : UInt
  data_status : Byte
  transfer_status : Byte
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_profinet(data : Bytes) -> ProfinetHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(6) {
    return None
  }
  let frame_id = reader.read_u16()

  // Real-Time (RT) Frames are typically 0x0100 - 0x0FFF or 0x8000 - 0xBBFF
  if (frame_id < 0x0100U || frame_id > 0x0FFFU) &&
    (frame_id < 0x8000U || frame_id > 0xBBFFU) {
    return None
  }

  let rem_len = reader.remaining()
  let body_len = if rem_len >= 4 { rem_len - 4 } else { rem_len }
  let payload = reader.read_bytes(body_len)

  let cycle_counter = if reader.has_bytes(2) { reader.read_u16() } else { 0U }
  let data_status = if reader.has_bytes(1) { reader.read_u8() } else { b'\x00' }
  let transfer_status = if reader.has_bytes(1) {
    reader.read_u8()
  } else {
    b'\x00'
  }

  Some({ frame_id, cycle_counter, data_status, transfer_status, payload })
}
