// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/base64.mbt

///|
pub fn base64_char(v : Int) -> Char {
  if v < 26 {
    (65 + v).unsafe_to_char()
  } else if v < 52 {
    (97 + (v - 26)).unsafe_to_char()
  } else if v < 62 {
    (48 + (v - 52)).unsafe_to_char()
  } else if v == 62 {
    '+'
  } else {
    '/'
  }
}

///|
pub fn base64_encode(bytes : Bytes) -> String {
  let buf = StringBuilder::new()
  let len = bytes.length()
  let mut i = 0

  while i < len {
    let b0 = bytes[i].to_int()
    let b1 = if i + 1 < len { bytes[i + 1].to_int() } else { 0 }
    let b2 = if i + 2 < len { bytes[i + 2].to_int() } else { 0 }

    let c0 = (b0 >> 2) & 0x3F
    let c1 = ((b0 & 0x03) << 4) | ((b1 >> 4) & 0x0F)
    let c2 = ((b1 & 0x0F) << 2) | ((b2 >> 6) & 0x03)
    let c3 = b2 & 0x3F

    buf.write_char(base64_char(c0))
    buf.write_char(base64_char(c1))

    if i + 1 < len {
      buf.write_char(base64_char(c2))
    } else {
      buf.write_char('=')
    }

    if i + 2 < len {
      buf.write_char(base64_char(c3))
    } else {
      buf.write_char('=')
    }

    i = i + 3
  }

  buf.to_string()
}
