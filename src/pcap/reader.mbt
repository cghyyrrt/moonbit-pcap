// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcap/reader.mbt

///|
pub struct PcapReader {
  global_header : PcapGlobalHeader
  reader : @binary.BinaryReader
  mut count : Int
}

///|
pub fn PcapReader::new(bytes : Bytes) -> PcapReader? {
  let reader = @binary.BinaryReader::new(bytes)
  match parse_magic(reader) {
    Some(global_header) => Some({ global_header, reader, count: 0 })
    None => None
  }
}

///|
pub fn PcapReader::get_global_header(self : PcapReader) -> PcapGlobalHeader {
  self.global_header
}

///|
pub fn PcapReader::read_next(self : PcapReader) -> PcapPacket? {
  if !self.reader.has_bytes(16) {
    return None
  }
  match parse_packet_header(self.reader, self.global_header.is_nanosecond) {
    Some(pkt_hdr) => {
      let cap_len = pkt_hdr.incl_len.reinterpret_as_int()
      if !self.reader.has_bytes(cap_len) {
        return None
      }
      let payload = self.reader.read_bytes(cap_len)
      let ts = calculate_timestamp(
        pkt_hdr.ts_sec,
        pkt_hdr.ts_usec,
        self.global_header.is_nanosecond,
      )
      self.count = self.count + 1
      Some({ header: pkt_hdr, payload, timestamp: ts })
    }
    None => None
  }
}

///|
pub fn PcapReader::read_all(self : PcapReader) -> Array[PcapPacket] {
  let packets = Array::new()
  while true {
    match self.read_next() {
      Some(pkt) => packets.push(pkt)
      None => break
    }
  }
  packets
}

///|
pub fn PcapReader::get_packet_count(self : PcapReader) -> Int {
  self.count
}

///|
pub struct PcapWriter {
  writer : @binary.BinaryWriter
  is_nanosecond : Bool
}

///|
pub fn PcapWriter::new(
  endian? : @binary.Endian = LittleEndian,
  nanosecond? : Bool = false,
  network? : UInt = 1U, // Ethernet
) -> PcapWriter {
  let writer = @binary.BinaryWriter::new(endian~)
  let magic = match (endian, nanosecond) {
    (LittleEndian, false) => 0xD4C3B2A1U
    (BigEndian, false) => 0xA1B2C3D4U
    (LittleEndian, true) => 0x4D3CB2A1U
    (BigEndian, true) => 0xA1B23C4DU
  }
  writer.write_u32(magic)
  writer.write_u16(2U) // Major
  writer.write_u16(4U) // Minor
  writer.write_u32(0U) // timezone
  writer.write_u32(0U) // sigfigs
  writer.write_u32(65535U) // snaplen
  writer.write_u32(network) // LinkType
  { writer, is_nanosecond: nanosecond }
}

///|
pub fn PcapWriter::write_packet(
  self : PcapWriter,
  payload : Bytes,
  ts_sec? : UInt = 0U,
  ts_usec? : UInt = 0U,
) -> Unit {
  let len = payload.length().reinterpret_as_uint()
  self.writer.write_u32(ts_sec)
  self.writer.write_u32(ts_usec)
  self.writer.write_u32(len)
  self.writer.write_u32(len)
  self.writer.write_bytes(payload)
}

///|
pub fn PcapWriter::to_bytes(self : PcapWriter) -> Bytes {
  self.writer.to_bytes()
}
