// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: binary/binary_writer.mbt

///|
pub struct BinaryWriter {
  buf : Array[Byte]
  mut endian : Endian
}

///|
pub fn BinaryWriter::new(endian? : Endian = LittleEndian) -> BinaryWriter {
  { buf: Array::new(), endian }
}

///|
pub fn BinaryWriter::get_endian(self : BinaryWriter) -> Endian {
  self.endian
}

///|
pub fn BinaryWriter::set_endian(self : BinaryWriter, endian : Endian) -> Unit {
  self.endian = endian
}

///|
pub fn BinaryWriter::write_u8(self : BinaryWriter, val : Byte) -> Unit {
  self.buf.push(val)
}

///|
pub fn BinaryWriter::write_u16(self : BinaryWriter, val : UInt) -> Unit {
  let b0 = (val & 0xFFU).reinterpret_as_int().to_byte()
  let b1 = ((val >> 8) & 0xFFU).reinterpret_as_int().to_byte()
  match self.endian {
    LittleEndian => {
      self.buf.push(b0)
      self.buf.push(b1)
    }
    BigEndian => {
      self.buf.push(b1)
      self.buf.push(b0)
    }
  }
}

///|
pub fn BinaryWriter::write_u24(self : BinaryWriter, val : UInt) -> Unit {
  let b0 = (val & 0xFFU).reinterpret_as_int().to_byte()
  let b1 = ((val >> 8) & 0xFFU).reinterpret_as_int().to_byte()
  let b2 = ((val >> 16) & 0xFFU).reinterpret_as_int().to_byte()
  match self.endian {
    LittleEndian => {
      self.buf.push(b0)
      self.buf.push(b1)
      self.buf.push(b2)
    }
    BigEndian => {
      self.buf.push(b2)
      self.buf.push(b1)
      self.buf.push(b0)
    }
  }
}

///|
pub fn BinaryWriter::write_u32(self : BinaryWriter, val : UInt) -> Unit {
  let b0 = (val & 0xFFU).reinterpret_as_int().to_byte()
  let b1 = ((val >> 8) & 0xFFU).reinterpret_as_int().to_byte()
  let b2 = ((val >> 16) & 0xFFU).reinterpret_as_int().to_byte()
  let b3 = ((val >> 24) & 0xFFU).reinterpret_as_int().to_byte()
  match self.endian {
    LittleEndian => {
      self.buf.push(b0)
      self.buf.push(b1)
      self.buf.push(b2)
      self.buf.push(b3)
    }
    BigEndian => {
      self.buf.push(b3)
      self.buf.push(b2)
      self.buf.push(b1)
      self.buf.push(b0)
    }
  }
}

///|
pub fn BinaryWriter::write_u64(self : BinaryWriter, val : UInt64) -> Unit {
  let b0 = (val & 0xFFUL).to_byte()
  let b1 = ((val >> 8) & 0xFFUL).to_byte()
  let b2 = ((val >> 16) & 0xFFUL).to_byte()
  let b3 = ((val >> 24) & 0xFFUL).to_byte()
  let b4 = ((val >> 32) & 0xFFUL).to_byte()
  let b5 = ((val >> 40) & 0xFFUL).to_byte()
  let b6 = ((val >> 48) & 0xFFUL).to_byte()
  let b7 = ((val >> 56) & 0xFFUL).to_byte()
  match self.endian {
    LittleEndian => {
      self.buf.push(b0)
      self.buf.push(b1)
      self.buf.push(b2)
      self.buf.push(b3)
      self.buf.push(b4)
      self.buf.push(b5)
      self.buf.push(b6)
      self.buf.push(b7)
    }
    BigEndian => {
      self.buf.push(b7)
      self.buf.push(b6)
      self.buf.push(b5)
      self.buf.push(b4)
      self.buf.push(b3)
      self.buf.push(b2)
      self.buf.push(b1)
      self.buf.push(b0)
    }
  }
}

///|
pub fn BinaryWriter::write_bytes(self : BinaryWriter, bytes : Bytes) -> Unit {
  for i = 0; i < bytes.length(); i = i + 1 {
    self.buf.push(bytes[i])
  }
}

///|
pub fn BinaryWriter::to_bytes(self : BinaryWriter) -> Bytes {
  Bytes::from_array(self.buf)
}

///|
pub fn BinaryWriter::length(self : BinaryWriter) -> Int {
  self.buf.length()
}
