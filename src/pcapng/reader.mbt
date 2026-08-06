// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcapng/reader.mbt

///|
pub struct PcapngReader {
  reader : @binary.BinaryReader
  interfaces : Array[InterfaceDescriptionBlock]
  mut current_shb : SectionHeaderBlock?
}

///|
pub fn PcapngReader::new(bytes : Bytes) -> PcapngReader {
  let reader = @binary.BinaryReader::new(bytes)
  { reader, interfaces: Array::new(), current_shb: None }
}

///|
pub fn PcapngReader::read_next_block(self : PcapngReader) -> PcapngBlock? {
  if !self.reader.has_bytes(12) {
    return None
  }
  let block_type = self.reader.read_u32()
  let block_len = self.reader.read_u32().reinterpret_as_int()

  if block_len < 12 || !self.reader.has_bytes(block_len - 12) {
    return None
  }

  let block_start = self.reader.tell() - 8
  let block_body_len = block_len - 12 // minus type(4), len(4), trailing len(4)

  let block = match block_type {
    0x0A0D0D0AU =>
      match parse_shb(self.reader, block_len) {
        Some(shb) => {
          self.current_shb = Some(shb)
          PcapngBlock::SectionHeader(shb)
        }
        None => PcapngBlock::UnknownBlock(block_type, block_len)
      }
    0x00000001U =>
      match parse_idb(self.reader, block_len) {
        Some(idb) => {
          self.interfaces.push(idb)
          PcapngBlock::InterfaceDescription(idb)
        }
        None => PcapngBlock::UnknownBlock(block_type, block_len)
      }
    0x00000006U => {
      let resol = if self.interfaces.length() > 0 {
        self.interfaces[0].ts_resolution
      } else {
        6
      }
      match parse_epb(self.reader, block_len, resol) {
        Some(epb) => PcapngBlock::EnhancedPacket(epb)
        None => PcapngBlock::UnknownBlock(block_type, block_len)
      }
    }
    0x00000003U =>
      if self.reader.has_bytes(4) {
        let orig_len = self.reader.read_u32()
        let cap_len = block_body_len - 4
        let packet_data = if cap_len > 0 {
          self.reader.read_bytes(cap_len)
        } else {
          Bytes::from_array([])
        }
        PcapngBlock::SimplePacket({ orig_len, packet_data })
      } else {
        PcapngBlock::UnknownBlock(block_type, block_len)
      }
    _ => {
      self.reader.skip(block_body_len)
      PcapngBlock::UnknownBlock(block_type, block_len)
    }
  }

  let end_pos = block_start + block_len - 4
  self.reader.seek(end_pos)
  let _trailing_len = self.reader.read_u32()
  Some(block)
}

///|
pub fn PcapngReader::read_all_packets(
  self : PcapngReader,
) -> Array[EnhancedPacketBlock] {
  let packets = Array::new()
  while true {
    match self.read_next_block() {
      Some(PcapngBlock::EnhancedPacket(epb)) => packets.push(epb)
      Some(_) => continue
      None => break
    }
  }
  packets
}

///|
pub struct PcapngWriter {
  writer : @binary.BinaryWriter
}

///|
pub fn PcapngWriter::new(
  endian? : @binary.Endian = LittleEndian,
) -> PcapngWriter {
  let writer = @binary.BinaryWriter::new(endian~)
  // Write SHB
  writer.write_u32(0x0A0D0D0AU)
  writer.write_u32(28U) // Block total len
  writer.write_u32(0x1A2B3C4DU) // BOM
  writer.write_u16(1U) // Major
  writer.write_u16(0U) // Minor
  writer.write_u64(0xFFFFFFFFFFFFFFFFUL) // Section len
  writer.write_u32(28U)

  // Write IDB
  writer.write_u32(0x00000001U)
  writer.write_u32(20U)
  writer.write_u16(1U) // LinkType Ethernet
  writer.write_u16(0U) // Reserved
  writer.write_u32(65535U) // SnapLen
  writer.write_u32(20U)

  PcapngWriter::{ writer, }
}

///|
pub fn PcapngWriter::write_enhanced_packet(
  self : PcapngWriter,
  payload : Bytes,
  ts_sec? : UInt = 0U,
  ts_usec? : UInt = 0U,
) -> Unit {
  let cap_len = payload.length()
  let pad = (4 - cap_len % 4) % 4
  let block_len = 32 + cap_len + pad

  self.writer.write_u32(0x00000006U) // EPB
  self.writer.write_u32(block_len.reinterpret_as_uint())
  self.writer.write_u32(0U) // Interface ID
  self.writer.write_u32(ts_sec)
  self.writer.write_u32(ts_usec)
  self.writer.write_u32(cap_len.reinterpret_as_uint())
  self.writer.write_u32(cap_len.reinterpret_as_uint())
  self.writer.write_bytes(payload)

  for i = 0; i < pad; i = i + 1 {
    self.writer.write_u8(b'\x00')
  }

  self.writer.write_u32(block_len.reinterpret_as_uint())
}

///|
pub fn PcapngWriter::to_bytes(self : PcapngWriter) -> Bytes {
  self.writer.to_bytes()
}
