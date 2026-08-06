// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/tcp.mbt

///|
pub(all) struct TcpOption {
  kind : Byte
  length : Byte
  data : Bytes
} derive(Eq, Debug)

///|
pub(all) struct TcpHeader {
  src_port : UInt
  dst_port : UInt
  seq_num : UInt
  ack_num : UInt
  data_offset : Byte
  flag_fin : Bool
  flag_syn : Bool
  flag_rst : Bool
  flag_psh : Bool
  flag_ack : Bool
  flag_urg : Bool
  flag_ece : Bool
  flag_cwr : Bool
  window_size : UInt
  checksum : UInt
  urgent_pointer : UInt
  options : Array[TcpOption]
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_tcp_options(data : Bytes) -> Array[TcpOption] {
  let options = Array::new()
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)

  while reader.has_bytes(1) {
    let kind = reader.read_u8()
    if kind == b'\x00' { // EOL
      options.push({ kind, length: b'\x01', data: Bytes::from_array([]) })
      break
    } else if kind == b'\x01' { // NOP
      options.push({ kind, length: b'\x01', data: Bytes::from_array([]) })
    } else {
      if !reader.has_bytes(1) {
        break
      }
      let length = reader.read_u8()
      let len_int = length.to_int()
      let data_len = if len_int >= 2 { len_int - 2 } else { 0 }
      let opt_data = if reader.has_bytes(data_len) {
        reader.read_bytes(data_len)
      } else {
        Bytes::from_array([])
      }
      options.push({ kind, length, data: opt_data })
    }
  }

  options
}

///|
pub fn parse_tcp(data : Bytes) -> TcpHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(20) {
    return None
  }
  let src_port = reader.read_u16()
  let dst_port = reader.read_u16()
  let seq_num = reader.read_u32()
  let ack_num = reader.read_u32()

  let do_flags = reader.read_u16()
  let data_offset = ((do_flags >> 12) & 0x0FU).reinterpret_as_int().to_byte()
  let flags_val = do_flags & 0x01FFU

  let flag_cwr = ((flags_val >> 7) & 0x01U) != 0U
  let flag_ece = ((flags_val >> 6) & 0x01U) != 0U
  let flag_urg = ((flags_val >> 5) & 0x01U) != 0U
  let flag_ack = ((flags_val >> 4) & 0x01U) != 0U
  let flag_psh = ((flags_val >> 3) & 0x01U) != 0U
  let flag_rst = ((flags_val >> 2) & 0x01U) != 0U
  let flag_syn = ((flags_val >> 1) & 0x01U) != 0U
  let flag_fin = (flags_val & 0x01U) != 0U

  let window_size = reader.read_u16()
  let checksum = reader.read_u16()
  let urgent_pointer = reader.read_u16()

  let header_bytes_len = data_offset.to_int() * 4
  if header_bytes_len < 20 {
    return None
  }

  let opt_len = header_bytes_len - 20
  let options = if opt_len > 0 && reader.has_bytes(opt_len) {
    let opt_bytes = reader.read_bytes(opt_len)
    parse_tcp_options(opt_bytes)
  } else {
    Array::new()
  }

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)

  Some({
    src_port,
    dst_port,
    seq_num,
    ack_num,
    data_offset,
    flag_fin,
    flag_syn,
    flag_rst,
    flag_psh,
    flag_ack,
    flag_urg,
    flag_ece,
    flag_cwr,
    window_size,
    checksum,
    urgent_pointer,
    options,
    payload,
  })
}
