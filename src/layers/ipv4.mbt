// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/ipv4.mbt

///|
pub(all) struct IPv4Header {
  version : Byte
  ihl : Byte
  dscp : Byte
  ecn : Byte
  total_length : UInt
  identification : UInt
  flags_df : Bool
  flags_mf : Bool
  fragment_offset : UInt
  ttl : Byte
  protocol : Byte
  checksum : UInt
  src_ip : Bytes
  dst_ip : Bytes
  options : Bytes
  payload : Bytes
  is_checksum_valid : Bool
} derive(Eq, Debug)

///|
pub fn parse_ipv4(data : Bytes) -> IPv4Header? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(20) {
    return None
  }
  let v_ihl = reader.read_u8().to_int()
  let version = ((v_ihl >> 4) & 0x0F).to_byte()
  let ihl = (v_ihl & 0x0F).to_byte()

  if version != b'\x04' || ihl < b'\x05' {
    return None
  }

  let tos = reader.read_u8().to_int()
  let dscp = ((tos >> 2) & 0x3F).to_byte()
  let ecn = (tos & 0x03).to_byte()

  let total_length = reader.read_u16()
  let identification = reader.read_u16()

  let flags_fo = reader.read_u16()
  let flags_df = ((flags_fo >> 14) & 0x01U) != 0U
  let flags_mf = ((flags_fo >> 13) & 0x01U) != 0U
  let fragment_offset = flags_fo & 0x1FFFU

  let ttl = reader.read_u8()
  let protocol = reader.read_u8()
  let checksum = reader.read_u16()

  let src_ip = reader.read_bytes(4)
  let dst_ip = reader.read_bytes(4)

  let header_bytes_len = ihl.to_int() * 4
  let opt_len = header_bytes_len - 20

  let options = if opt_len > 0 && reader.has_bytes(opt_len) {
    reader.read_bytes(opt_len)
  } else {
    Bytes::from_array([])
  }

  let total_len_int = total_length.reinterpret_as_int()
  let payload_len = if total_len_int >= header_bytes_len {
    total_len_int - header_bytes_len
  } else {
    reader.remaining()
  }

  let payload = if reader.has_bytes(payload_len) {
    reader.read_bytes(payload_len)
  } else {
    reader.read_bytes(reader.remaining())
  }

  let is_checksum_valid = @binary.verify_internet_checksum(
    data, 0, header_bytes_len,
  )

  Some({
    version,
    ihl,
    dscp,
    ecn,
    total_length,
    identification,
    flags_df,
    flags_mf,
    fragment_offset,
    ttl,
    protocol,
    checksum,
    src_ip,
    dst_ip,
    options,
    payload,
    is_checksum_valid,
  })
}
