// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/bit_reader.mbt

///|
pub struct BitReader {
  bytes : Bytes
  mut byte_offset : Int
  mut bit_offset : Int
}

///|
pub fn BitReader::new(bytes : Bytes) -> BitReader {
  { bytes, byte_offset: 0, bit_offset: 0 }
}

///|
pub fn BitReader::remaining_bits(self : BitReader) -> Int {
  let total_bits = self.bytes.length() * 8
  let current_bit = self.byte_offset * 8 + self.bit_offset
  if current_bit >= total_bits {
    0
  } else {
    total_bits - current_bit
  }
}

///|
pub fn BitReader::read_bit(self : BitReader) -> Bool {
  if self.byte_offset >= self.bytes.length() {
    false
  } else {
    let b = self.bytes[self.byte_offset].to_int()
    let shift = 7 - self.bit_offset
    let bit = ((b >> shift) & 1) != 0
    self.bit_offset = self.bit_offset + 1
    if self.bit_offset == 8 {
      self.bit_offset = 0
      self.byte_offset = self.byte_offset + 1
    }
    bit
  }
}

///|
pub fn BitReader::read_bits(self : BitReader, n : Int) -> UInt {
  if n <= 0 || n > 32 {
    return 0U
  }
  let mut res = 0U
  for i = 0; i < n; i = i + 1 {
    let bit_val = if self.read_bit() { 1U } else { 0U }
    res = (res << 1) | bit_val
  }
  res
}

///|
pub fn BitReader::read_ue(self : BitReader) -> UInt {
  // Unsigned Exponential-Golomb code reader
  let mut leading_zeros = 0
  while self.remaining_bits() > 0 && !self.read_bit() {
    leading_zeros = leading_zeros + 1
  }
  if leading_zeros == 0 {
    0U
  } else {
    let info = self.read_bits(leading_zeros)
    let base = (1U << leading_zeros) - 1U
    base + info
  }
}

///|
pub fn BitReader::read_se(self : BitReader) -> Int {
  // Signed Exponential-Golomb code reader
  let code_num = self.read_ue().reinterpret_as_int()
  if (code_num & 1) != 0 {
    (code_num + 1) / 2
  } else {
    -(code_num / 2)
  }
}

///|
pub fn BitReader::align_to_byte(self : BitReader) -> Unit {
  if self.bit_offset > 0 {
    self.bit_offset = 0
    self.byte_offset = self.byte_offset + 1
  }
}
