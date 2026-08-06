// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/checksum.mbt

///|
pub fn internet_checksum(bytes : Bytes, offset : Int, len : Int) -> UInt {
  let mut sum = 0U
  let end_pos = offset + len
  let mut i = offset

  while i + 1 < end_pos {
    let b0 = bytes[i].to_uint()
    let b1 = bytes[i + 1].to_uint()
    let word = (b0 << 8) | b1
    sum = sum + word
    i = i + 2
  }

  if i < end_pos {
    let b0 = bytes[i].to_uint()
    let word = b0 << 8
    sum = sum + word
  }

  while sum >> 16 > 0U {
    sum = (sum & 0xFFFFU) + (sum >> 16)
  }

  let final_sum = (sum ^ 0xFFFFU) & 0xFFFFU
  final_sum
}

///|
pub fn verify_internet_checksum(bytes : Bytes, offset : Int, len : Int) -> Bool {
  let csum = internet_checksum(bytes, offset, len)
  csum == 0U
}

///|
pub fn crc32(bytes : Bytes) -> UInt {
  let mut crc = 0xFFFFFFFFU
  let polynomial = 0xEDB88320U
  let len = bytes.length()

  for i = 0; i < len; i = i + 1 {
    let b = bytes[i].to_uint()
    crc = crc ^ b
    for j = 0; j < 8; j = j + 1 {
      let mask = (crc & 1U) ^ 1U
      if mask == 0U {
        crc = (crc >> 1) ^ polynomial
      } else {
        crc = crc >> 1
      }
    }
  }

  crc ^ 0xFFFFFFFFU
}
