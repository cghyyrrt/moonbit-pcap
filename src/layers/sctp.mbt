// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/sctp.mbt

///|
pub(all) struct SctpChunk {
  chunk_type : Byte
  chunk_flags : Byte
  chunk_length : UInt
  chunk_data : Bytes
} derive(Eq, Debug)

///|
pub(all) struct SctpHeader {
  src_port : UInt
  dst_port : UInt
  verification_tag : UInt
  checksum : UInt
  chunks : Array[SctpChunk]
} derive(Eq, Debug)

///|
pub fn parse_sctp(data : Bytes) -> SctpHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(12) {
    return None
  }
  let src_port = reader.read_u16()
  let dst_port = reader.read_u16()
  let verification_tag = reader.read_u32()
  let checksum = reader.read_u32()

  let chunks = Array::new()
  while reader.has_bytes(4) {
    let chunk_type = reader.read_u8()
    let chunk_flags = reader.read_u8()
    let chunk_length = reader.read_u16()
    let len_int = chunk_length.reinterpret_as_int()
    let body_len = if len_int >= 4 { len_int - 4 } else { 0 }
    let chunk_data = if reader.has_bytes(body_len) {
      reader.read_bytes(body_len)
    } else {
      Bytes::from_array([])
    }
    chunks.push({ chunk_type, chunk_flags, chunk_length, chunk_data })

    // Align to 4-byte boundary
    let pad = (4 - len_int % 4) % 4
    if pad > 0 && reader.has_bytes(pad) {
      reader.skip(pad)
    }
  }

  Some({ src_port, dst_port, verification_tag, checksum, chunks })
}
