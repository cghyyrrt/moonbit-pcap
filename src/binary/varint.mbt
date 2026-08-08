// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/varint.mbt

///|
pub fn encode_varint_u64(val : UInt64) -> Bytes {
  let buf = Array::new()
  let mut v = val
  while v >= 0x80UL {
    let b = ((v & 0x7FUL) | 0x80UL).to_byte()
    buf.push(b)
    v = v >> 7
  }
  buf.push(v.to_byte())
  Bytes::from_array(buf)
}

///|
pub fn decode_varint_u64(reader : BinaryReader) -> UInt64 {
  let mut res = 0UL
  let mut shift = 0
  while reader.has_bytes(1) && shift < 64 {
    let b = reader.read_u8().to_uint64()
    let val = b & 0x7FUL
    res = res | (val << shift)
    if (b & 0x80UL) == 0UL {
      break
    }
    shift = shift + 7
  }
  res
}

///|
pub fn encode_zigzag_i64(n : Int64) -> UInt64 {
  let u = n.reinterpret_as_uint64()
  if n < 0L {
    (u << 1) ^ 0xFFFFFFFFFFFFFFFFUL
  } else {
    u << 1
  }
}

///|
pub fn decode_zigzag_i64(u : UInt64) -> Int64 {
  let n = (u >> 1).reinterpret_as_int64()
  if (u & 1UL) != 0UL {
    -n - 1L
  } else {
    n
  }
}
