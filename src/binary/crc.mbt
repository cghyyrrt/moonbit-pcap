// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/crc.mbt

///|
pub fn crc16_modbus(bytes : Bytes) -> UInt {
  let mut crc = 0xFFFFU
  let len = bytes.length()
  for i = 0; i < len; i = i + 1 {
    let b = bytes[i].to_uint()
    crc = crc ^ b
    for j = 0; j < 8; j = j + 1 {
      if (crc & 0x0001U) != 0U {
        crc = (crc >> 1) ^ 0xA001U
      } else {
        crc = crc >> 1
      }
    }
  }
  crc
}

///|
pub fn crc16_ccitt(bytes : Bytes) -> UInt {
  let mut crc = 0xFFFFU
  let len = bytes.length()
  for i = 0; i < len; i = i + 1 {
    let b = bytes[i].to_uint()
    crc = crc ^ (b << 8)
    for j = 0; j < 8; j = j + 1 {
      if (crc & 0x8000U) != 0U {
        crc = ((crc << 1) ^ 0x1021U) & 0xFFFFU
      } else {
        crc = (crc << 1) & 0xFFFFU
      }
    }
  }
  crc
}

///|
pub fn crc8(bytes : Bytes) -> Byte {
  let mut crc = 0x00
  let len = bytes.length()
  for i = 0; i < len; i = i + 1 {
    let b = bytes[i].to_int()
    crc = crc ^ b
    for j = 0; j < 8; j = j + 1 {
      if (crc & 0x80) != 0 {
        crc = ((crc << 1) ^ 0x07) & 0xFF
      } else {
        crc = (crc << 1) & 0xFF
      }
    }
  }
  crc.to_byte()
}

///|
pub fn adler32(bytes : Bytes) -> UInt {
  let mut a = 1U
  let mut b = 0U
  let mod_adler = 65521U
  let len = bytes.length()

  for i = 0; i < len; i = i + 1 {
    let val = bytes[i].to_uint()
    a = (a + val) % mod_adler
    b = (b + a) % mod_adler
  }

  (b << 16) | a
}
