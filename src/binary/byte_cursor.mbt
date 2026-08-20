// A non-panicking cursor for protocol parsers that need transactional reads.

///|
pub(all) struct CursorMark {
  position : Int
} derive(Eq, Debug)

///|
pub struct ByteCursor {
  bytes : Bytes
  mut position : Int
}

///|
/// Create a cursor at byte zero.
pub fn ByteCursor::new(bytes : Bytes) -> ByteCursor {
  { bytes, position: 0 }
}

///|
/// Return the current byte position.
pub fn ByteCursor::position(self : ByteCursor) -> Int {
  self.position
}

///|
/// Return bytes that have not been consumed.
pub fn ByteCursor::remaining(self : ByteCursor) -> Int {
  self.bytes.length() - self.position
}

///|
/// Return whether no bytes remain.
pub fn ByteCursor::at_end(self : ByteCursor) -> Bool {
  self.position >= self.bytes.length()
}

///|
/// Save a position for a later reset.
pub fn ByteCursor::mark(self : ByteCursor) -> CursorMark {
  { position: self.position }
}

///|
/// Reset to a mark created by this cursor.
pub fn ByteCursor::reset(self : ByteCursor, mark : CursorMark) -> Unit {
  if mark.position >= 0 && mark.position <= self.bytes.length() {
    self.position = mark.position
  }
}

///|
/// Return the next byte without consuming it.
pub fn ByteCursor::peek_u8(self : ByteCursor) -> Byte? {
  if self.position < self.bytes.length() {
    Some(self.bytes[self.position])
  } else {
    None
  }
}

///|
/// Consume and return one byte.
pub fn ByteCursor::read_u8(self : ByteCursor) -> Byte? {
  match self.peek_u8() {
    Some(value) => {
      self.position = self.position + 1
      Some(value)
    }
    None => None
  }
}

///|
/// Return a bounded byte slice and advance only on success.
pub fn ByteCursor::take(self : ByteCursor, length : Int) -> Bytes? {
  if length < 0 || length > self.remaining() {
    return None
  }
  let start = self.position
  let result = BinaryReader::new(self.bytes, offset=start).read_bytes(length)
  self.position = self.position + length
  Some(result)
}

///|
/// Skip bytes only when the complete range is available.
pub fn ByteCursor::skip(self : ByteCursor, length : Int) -> Bool {
  if length < 0 || length > self.remaining() {
    false
  } else {
    self.position = self.position + length
    true
  }
}

///|
/// Read an unsigned little-endian 16-bit value.
pub fn ByteCursor::read_u16_le(self : ByteCursor) -> UInt? {
  if self.remaining() < 2 {
    return None
  }
  let value = self.bytes[self.position].to_uint() |
    (self.bytes[self.position + 1].to_uint() << 8)
  self.position = self.position + 2
  Some(value)
}

///|
/// Read an unsigned big-endian 16-bit value.
pub fn ByteCursor::read_u16_be(self : ByteCursor) -> UInt? {
  if self.remaining() < 2 {
    return None
  }
  let value = (self.bytes[self.position].to_uint() << 8) |
    self.bytes[self.position + 1].to_uint()
  self.position = self.position + 2
  Some(value)
}

///|
/// Read an unsigned little-endian 24-bit value.
pub fn ByteCursor::read_u24_le(self : ByteCursor) -> UInt? {
  if self.remaining() < 3 {
    return None
  }
  let value = self.bytes[self.position].to_uint() |
    (self.bytes[self.position + 1].to_uint() << 8) |
    (self.bytes[self.position + 2].to_uint() << 16)
  self.position = self.position + 3
  Some(value)
}

///|
/// Read an unsigned big-endian 24-bit value.
pub fn ByteCursor::read_u24_be(self : ByteCursor) -> UInt? {
  if self.remaining() < 3 {
    return None
  }
  let value = (self.bytes[self.position].to_uint() << 16) |
    (self.bytes[self.position + 1].to_uint() << 8) |
    self.bytes[self.position + 2].to_uint()
  self.position = self.position + 3
  Some(value)
}

///|
/// Read an unsigned little-endian 32-bit value.
pub fn ByteCursor::read_u32_le(self : ByteCursor) -> UInt? {
  if self.remaining() < 4 {
    return None
  }
  let value = self.bytes[self.position].to_uint() |
    (self.bytes[self.position + 1].to_uint() << 8) |
    (self.bytes[self.position + 2].to_uint() << 16) |
    (self.bytes[self.position + 3].to_uint() << 24)
  self.position = self.position + 4
  Some(value)
}

///|
/// Read an unsigned big-endian 32-bit value.
pub fn ByteCursor::read_u32_be(self : ByteCursor) -> UInt? {
  if self.remaining() < 4 {
    return None
  }
  let value = (self.bytes[self.position].to_uint() << 24) |
    (self.bytes[self.position + 1].to_uint() << 16) |
    (self.bytes[self.position + 2].to_uint() << 8) |
    self.bytes[self.position + 3].to_uint()
  self.position = self.position + 4
  Some(value)
}

///|
/// Read an unsigned little-endian 64-bit value.
pub fn ByteCursor::read_u64_le(self : ByteCursor) -> UInt64? {
  if self.remaining() < 8 {
    return None
  }
  let mut value = 0UL
  for i = 0; i < 8; i = i + 1 {
    value = value | (self.bytes[self.position + i].to_uint64() << (i * 8))
  }
  self.position = self.position + 8
  Some(value)
}

///|
/// Read an unsigned big-endian 64-bit value.
pub fn ByteCursor::read_u64_be(self : ByteCursor) -> UInt64? {
  if self.remaining() < 8 {
    return None
  }
  let mut value = 0UL
  for i = 0; i < 8; i = i + 1 {
    value = value | (self.bytes[self.position + i].to_uint64() << ((7 - i) * 8))
  }
  self.position = self.position + 8
  Some(value)
}

///|
/// Read a signed little-endian 16-bit value.
pub fn ByteCursor::read_i16_le(self : ByteCursor) -> Int? {
  match self.read_u16_le() {
    None => None
    Some(value) =>
      Some(
        if value >= 32768U {
          value.reinterpret_as_int() - 65536
        } else {
          value.reinterpret_as_int()
        },
      )
  }
}

///|
/// Read a signed big-endian 16-bit value.
pub fn ByteCursor::read_i16_be(self : ByteCursor) -> Int? {
  match self.read_u16_be() {
    None => None
    Some(value) =>
      Some(
        if value >= 32768U {
          value.reinterpret_as_int() - 65536
        } else {
          value.reinterpret_as_int()
        },
      )
  }
}

///|
/// Read a bounded length-prefixed byte field with an 8-bit length.
pub fn ByteCursor::read_u8_length_prefixed(self : ByteCursor) -> Bytes? {
  match self.read_u8() {
    None => None
    Some(length) => self.take(length.to_int())
  }
}

///|
/// Read a bounded length-prefixed byte field with a little-endian 16-bit length.
pub fn ByteCursor::read_u16_length_prefixed_le(self : ByteCursor) -> Bytes? {
  match self.read_u16_le() {
    None => None
    Some(length) => self.take(length.reinterpret_as_int())
  }
}

///|
/// Read a bounded length-prefixed byte field with a big-endian 16-bit length.
pub fn ByteCursor::read_u16_length_prefixed_be(self : ByteCursor) -> Bytes? {
  match self.read_u16_be() {
    None => None
    Some(length) => self.take(length.reinterpret_as_int())
  }
}

///|
/// Read an unsigned LEB128 value with a ten-byte safety bound.
pub fn ByteCursor::read_varuint(self : ByteCursor) -> UInt64? {
  let mark = self.mark()
  let mut value = 0UL
  let mut shift = 0
  for _i = 0; _i < 10; _i = _i + 1 {
    match self.read_u8() {
      None => {
        self.reset(mark)
        return None
      }
      Some(byte) => {
        value = value | ((byte.to_uint64() & 0x7FUL) << shift)
        if (byte.to_int() & 0x80) == 0 {
          return Some(value)
        }
        shift = shift + 7
      }
    }
  }
  self.reset(mark)
  None
}

///|
/// Search for a byte sequence without moving the cursor.
pub fn ByteCursor::contains(self : ByteCursor, needle : Bytes) -> Bool {
  if needle.length() == 0 {
    return true
  }
  if needle.length() > self.remaining() {
    return false
  }
  for start = self.position
      start <= self.bytes.length() - needle.length()
      start = start + 1 {
    let mut found = true
    for i = 0; i < needle.length(); i = i + 1 {
      if self.bytes[start + i] != needle[i] {
        found = false
        break
      }
    }
    if found {
      return true
    }
  }
  false
}
