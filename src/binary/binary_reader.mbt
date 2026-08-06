// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/binary_reader.mbt

///|
pub(all) enum Endian {
  LittleEndian
  BigEndian
} derive(Eq, Debug)

///|
pub struct BinaryReader {
  bytes : Bytes
  mut offset : Int
  mut endian : Endian
}

///|
pub fn BinaryReader::new(
  bytes : Bytes,
  offset? : Int = 0,
  endian? : Endian = LittleEndian,
) -> BinaryReader {
  { bytes, offset, endian }
}

///|
pub fn BinaryReader::get_endian(self : BinaryReader) -> Endian {
  self.endian
}

///|
pub fn BinaryReader::set_endian(self : BinaryReader, endian : Endian) -> Unit {
  self.endian = endian
}

///|
pub fn BinaryReader::remaining(self : BinaryReader) -> Int {
  let len = self.bytes.length()
  if self.offset >= len {
    0
  } else {
    len - self.offset
  }
}

///|
pub fn BinaryReader::has_bytes(self : BinaryReader, n : Int) -> Bool {
  self.remaining() >= n
}

///|
pub fn BinaryReader::tell(self : BinaryReader) -> Int {
  self.offset
}

///|
pub fn BinaryReader::seek(self : BinaryReader, pos : Int) -> Unit {
  let len = self.bytes.length()
  if pos < 0 {
    self.offset = 0
  } else if pos > len {
    self.offset = len
  } else {
    self.offset = pos
  }
}

///|
pub fn BinaryReader::skip(self : BinaryReader, n : Int) -> Unit {
  self.seek(self.offset + n)
}

///|
pub fn BinaryReader::read_u8(self : BinaryReader) -> Byte {
  if self.offset >= self.bytes.length() {
    b'\x00'
  } else {
    let b = self.bytes[self.offset]
    self.offset = self.offset + 1
    b
  }
}

///|
pub fn BinaryReader::read_u16(self : BinaryReader) -> UInt {
  if !self.has_bytes(2) {
    return 0U
  }
  let b0 = self.bytes[self.offset].to_uint()
  let b1 = self.bytes[self.offset + 1].to_uint()
  self.offset = self.offset + 2
  match self.endian {
    LittleEndian => b0 | (b1 << 8)
    BigEndian => (b0 << 8) | b1
  }
}

///|
pub fn BinaryReader::read_u24(self : BinaryReader) -> UInt {
  if !self.has_bytes(3) {
    return 0U
  }
  let b0 = self.bytes[self.offset].to_uint()
  let b1 = self.bytes[self.offset + 1].to_uint()
  let b2 = self.bytes[self.offset + 2].to_uint()
  self.offset = self.offset + 3
  match self.endian {
    LittleEndian => b0 | (b1 << 8) | (b2 << 16)
    BigEndian => (b0 << 16) | (b1 << 8) | b2
  }
}

///|
pub fn BinaryReader::read_u32(self : BinaryReader) -> UInt {
  if !self.has_bytes(4) {
    return 0U
  }
  let b0 = self.bytes[self.offset].to_uint()
  let b1 = self.bytes[self.offset + 1].to_uint()
  let b2 = self.bytes[self.offset + 2].to_uint()
  let b3 = self.bytes[self.offset + 3].to_uint()
  self.offset = self.offset + 4
  match self.endian {
    LittleEndian => b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    BigEndian => (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
  }
}

///|
pub fn BinaryReader::read_u64(self : BinaryReader) -> UInt64 {
  if !self.has_bytes(8) {
    return 0UL
  }
  let b0 = self.bytes[self.offset].to_uint64()
  let b1 = self.bytes[self.offset + 1].to_uint64()
  let b2 = self.bytes[self.offset + 2].to_uint64()
  let b3 = self.bytes[self.offset + 3].to_uint64()
  let b4 = self.bytes[self.offset + 4].to_uint64()
  let b5 = self.bytes[self.offset + 5].to_uint64()
  let b6 = self.bytes[self.offset + 6].to_uint64()
  let b7 = self.bytes[self.offset + 7].to_uint64()
  self.offset = self.offset + 8
  match self.endian {
    LittleEndian =>
      b0 |
      (b1 << 8) |
      (b2 << 16) |
      (b3 << 24) |
      (b4 << 32) |
      (b5 << 40) |
      (b6 << 48) |
      (b7 << 56)
    BigEndian =>
      (b0 << 56) |
      (b1 << 48) |
      (b2 << 40) |
      (b3 << 32) |
      (b4 << 24) |
      (b5 << 16) |
      (b6 << 8) |
      b7
  }
}

///|
pub fn BinaryReader::read_i16(self : BinaryReader) -> Int {
  let u = self.read_u16().reinterpret_as_int()
  if u >= 32768 {
    u - 65536
  } else {
    u
  }
}

///|
pub fn BinaryReader::read_i32(self : BinaryReader) -> Int {
  self.read_u32().reinterpret_as_int()
}

///|
pub fn BinaryReader::read_bytes(self : BinaryReader, len : Int) -> Bytes {
  if len <= 0 || !self.has_bytes(len) {
    Bytes::from_array([])
  } else {
    let arr : Array[Byte] = Array::make(len, b'\x00')
    for i = 0; i < len; i = i + 1 {
      arr[i] = self.bytes[self.offset + i]
    }
    self.offset = self.offset + len
    Bytes::from_array(arr)
  }
}

///|
pub fn BinaryReader::peek_u8(self : BinaryReader) -> Byte {
  if self.offset >= self.bytes.length() {
    b'\x00'
  } else {
    self.bytes[self.offset]
  }
}

///|
pub fn BinaryReader::peek_u16(self : BinaryReader) -> UInt {
  let pos = self.offset
  let res = self.read_u16()
  self.offset = pos
  res
}

///|
pub fn BinaryReader::peek_u32(self : BinaryReader) -> UInt {
  let pos = self.offset
  let res = self.read_u32()
  self.offset = pos
  res
}
