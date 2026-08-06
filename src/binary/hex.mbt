// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/hex.mbt

///|
pub fn nibble_to_hex_char(nibble : Byte) -> Char {
  let v = nibble.to_int() & 0x0F
  if v < 10 {
    (48 + v).unsafe_to_char()
  } else {
    (97 + (v - 10)).unsafe_to_char()
  }
}

///|
pub fn byte_to_hex(b : Byte) -> String {
  let high = (b.to_int() >> 4) & 0x0F
  let low = b.to_int() & 0x0F
  let c1 = nibble_to_hex_char(high.to_byte())
  let c2 = nibble_to_hex_char(low.to_byte())
  "\{c1}\{c2}"
}

///|
pub fn bytes_to_hex(bytes : Bytes, separator? : String = "") -> String {
  let buf = StringBuilder::new()
  let len = bytes.length()
  for i = 0; i < len; i = i + 1 {
    if i > 0 && separator.length() > 0 {
      buf.write_string(separator)
    }
    buf.write_string(byte_to_hex(bytes[i]))
  }
  buf.to_string()
}

///|
pub fn mac_to_string(bytes : Bytes, offset? : Int = 0) -> String {
  if bytes.length() < offset + 6 {
    "00:00:00:00:00:00"
  } else {
    let b0 = byte_to_hex(bytes[offset])
    let b1 = byte_to_hex(bytes[offset + 1])
    let b2 = byte_to_hex(bytes[offset + 2])
    let b3 = byte_to_hex(bytes[offset + 3])
    let b4 = byte_to_hex(bytes[offset + 4])
    let b5 = byte_to_hex(bytes[offset + 5])
    "\{b0}:\{b1}:\{b2}:\{b3}:\{b4}:\{b5}"
  }
}

///|
pub fn ip4_to_string(bytes : Bytes, offset? : Int = 0) -> String {
  if bytes.length() < offset + 4 {
    "0.0.0.0"
  } else {
    let b0 = bytes[offset].to_int()
    let b1 = bytes[offset + 1].to_int()
    let b2 = bytes[offset + 2].to_int()
    let b3 = bytes[offset + 3].to_int()
    "\{b0}.\{b1}.\{b2}.\{b3}"
  }
}

///|
pub fn ip6_to_string(bytes : Bytes, offset? : Int = 0) -> String {
  if bytes.length() < offset + 16 {
    "::"
  } else {
    let buf = StringBuilder::new()
    for i = 0; i < 8; i = i + 1 {
      if i > 0 {
        buf.write_string(":")
      }
      let idx = offset + i * 2
      let hex_val = byte_to_hex(bytes[idx]) + byte_to_hex(bytes[idx + 1])
      buf.write_string(hex_val)
    }
    buf.to_string()
  }
}

///|
pub fn hex_dump(bytes : Bytes, max_len? : Int = 64) -> String {
  let buf = StringBuilder::new()
  let len = if bytes.length() < max_len { bytes.length() } else { max_len }
  for i = 0; i < len; i = i + 1 {
    if i > 0 && i % 16 == 0 {
      buf.write_string("\n")
    } else if i > 0 {
      buf.write_string(" ")
    }
    buf.write_string(byte_to_hex(bytes[i]))
  }
  if bytes.length() > max_len {
    buf.write_string("... (\{bytes.length() - max_len} bytes truncated)")
  }
  buf.to_string()
}
