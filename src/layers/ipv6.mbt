// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/ipv6.mbt

///|
pub(all) struct IPv6ExtHeader {
  next_header : Byte
  length : Int
  header_type : String
  data : Bytes
} derive(Eq, Debug)

///|
pub(all) struct IPv6Header {
  version : Byte
  traffic_class : Byte
  flow_label : UInt
  payload_length : UInt
  next_header : Byte
  hop_limit : Byte
  src_ip : Bytes
  dst_ip : Bytes
  extension_headers : Array[IPv6ExtHeader]
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_ipv6(data : Bytes) -> IPv6Header? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(40) {
    return None
  }
  let v_tc_fl = reader.read_u32()
  let version = ((v_tc_fl >> 28) & 0x0FU).reinterpret_as_int().to_byte()
  if version != b'\x06' {
    return None
  }

  let traffic_class = ((v_tc_fl >> 20) & 0xFFU).reinterpret_as_int().to_byte()
  let flow_label = v_tc_fl & 0xFFFFF_U

  let payload_length = reader.read_u16()
  let mut curr_next_hdr = reader.read_u8()
  let hop_limit = reader.read_u8()

  let src_ip = reader.read_bytes(16)
  let dst_ip = reader.read_bytes(16)

  let extension_headers = Array::new()

  // Traversal for extension headers (0 = Hop-by-Hop, 43 = Routing, 44 = Fragment, 60 = Destination Options)
  while curr_next_hdr == b'\x00' ||
        curr_next_hdr == b'\x2B' ||
        curr_next_hdr == b'\x2C' ||
        curr_next_hdr == b'\x3C' {
    if !reader.has_bytes(2) {
      break
    }
    let nxt = reader.read_u8()
    let len_hdr = reader.read_u8().to_int()
    let ext_byte_len = (len_hdr + 1) * 8 - 2
    if !reader.has_bytes(ext_byte_len) {
      break
    }
    let ext_data = reader.read_bytes(ext_byte_len)
    let type_str = match curr_next_hdr {
      b'\x00' => "Hop-by-Hop Options"
      b'\x2B' => "Routing"
      b'\x2C' => "Fragment"
      b'\x3C' => "Destination Options"
      _ => "Unknown Extension"
    }
    extension_headers.push({
      next_header: nxt,
      length: ext_byte_len + 2,
      header_type: type_str,
      data: ext_data,
    })
    curr_next_hdr = nxt
  }

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)

  Some({
    version,
    traffic_class,
    flow_label,
    payload_length,
    next_header: curr_next_hdr,
    hop_limit,
    src_ip,
    dst_ip,
    extension_headers,
    payload,
  })
}
