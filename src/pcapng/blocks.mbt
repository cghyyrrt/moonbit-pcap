// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcapng/blocks.mbt

///|
pub(all) struct SectionHeaderBlock {
  byte_order_magic : UInt
  major_version : UInt
  minor_version : UInt
  section_length : Int64
  endian : @binary.Endian
  options : Array[PcapngOption]
} derive(Eq, Debug)

///|
pub(all) struct InterfaceDescriptionBlock {
  link_type : UInt
  reserved : UInt
  snap_len : UInt
  options : Array[PcapngOption]
  ts_resolution : Int // ts_resol in log10 (default 6 = microsec)
} derive(Eq, Debug)

///|
pub(all) struct EnhancedPacketBlock {
  interface_id : UInt
  timestamp_high : UInt
  timestamp_low : UInt
  cap_len : UInt
  orig_len : UInt
  packet_data : Bytes
  options : Array[PcapngOption]
  timestamp : Double
} derive(Eq, Debug)

///|
pub(all) struct SimplePacketBlock {
  orig_len : UInt
  packet_data : Bytes
} derive(Eq, Debug)

///|
pub(all) enum PcapngBlock {
  SectionHeader(SectionHeaderBlock)
  InterfaceDescription(InterfaceDescriptionBlock)
  EnhancedPacket(EnhancedPacketBlock)
  SimplePacket(SimplePacketBlock)
  UnknownBlock(UInt, Int)
} derive(Eq, Debug)

///|
pub fn parse_shb(
  reader : @binary.BinaryReader,
  total_len : Int,
) -> SectionHeaderBlock? {
  if total_len < 28 || !reader.has_bytes(16) {
    return None
  }
  let bom = reader.read_u32()
  let endian = if bom == 0x1A2B3C4DU {
    @binary.LittleEndian
  } else {
    @binary.BigEndian
  }
  reader.set_endian(endian)

  let major = reader.read_u16()
  let minor = reader.read_u16()
  let sec_len = reader.read_u64().reinterpret_as_int64()
  let opt_bytes_len = total_len - 28
  let options = if opt_bytes_len > 0 {
    parse_options(reader, opt_bytes_len)
  } else {
    Array::new()
  }

  Some({
    byte_order_magic: bom,
    major_version: major,
    minor_version: minor,
    section_length: sec_len,
    endian,
    options,
  })
}

///|
pub fn parse_idb(
  reader : @binary.BinaryReader,
  total_len : Int,
) -> InterfaceDescriptionBlock? {
  if total_len < 20 || !reader.has_bytes(8) {
    return None
  }
  let link_type = reader.read_u16()
  let reserved = reader.read_u16()
  let snap_len = reader.read_u32()

  let opt_bytes_len = total_len - 20
  let options = if opt_bytes_len > 0 {
    parse_options(reader, opt_bytes_len)
  } else {
    Array::new()
  }

  let mut ts_resol = 6
  for opt in options {
    if opt.code == 9U && opt.value.length() > 0 { // if_tsresol
      let raw_v = opt.value[0].to_int()
      let exp = raw_v & 0x7F
      ts_resol = exp
    }
  }

  Some({ link_type, reserved, snap_len, options, ts_resolution: ts_resol })
}

///|
pub fn parse_epb(
  reader : @binary.BinaryReader,
  total_len : Int,
  ts_resol : Int,
) -> EnhancedPacketBlock? {
  if total_len < 32 || !reader.has_bytes(20) {
    return None
  }
  let interface_id = reader.read_u32()
  let ts_high = reader.read_u32()
  let ts_low = reader.read_u32()
  let cap_len = reader.read_u32()
  let orig_len = reader.read_u32()

  let cap_len_int = cap_len.reinterpret_as_int()
  if !reader.has_bytes(cap_len_int) {
    return None
  }
  let packet_data = reader.read_bytes(cap_len_int)

  let pad = (4 - cap_len_int % 4) % 4
  if pad > 0 && reader.has_bytes(pad) {
    reader.skip(pad)
  }

  let header_and_data_len = 32 + cap_len_int + pad
  let opt_bytes_len = total_len - header_and_data_len
  let options = if opt_bytes_len > 0 {
    parse_options(reader, opt_bytes_len)
  } else {
    Array::new()
  }

  let ts_ticks = (ts_high.to_uint64() << 32) | ts_low.to_uint64()
  let divider = match ts_resol {
    3 => 1000.0
    9 => 1000000000.0
    _ => 1000000.0
  }
  let ts = ts_ticks.reinterpret_as_int64().to_double() / divider

  Some({
    interface_id,
    timestamp_high: ts_high,
    timestamp_low: ts_low,
    cap_len,
    orig_len,
    packet_data,
    options,
    timestamp: ts,
  })
}
