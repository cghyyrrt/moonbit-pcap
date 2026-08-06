// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcap/header.mbt

///|
pub(all) enum PcapMagic {
  MicrosecondLittle // 0xd4c3b2a1
  MicrosecondBig // 0xa1b2c3d4
  NanosecondLittle // 0x4d3cb2a1
  NanosecondBig // 0xa1b23c4d
} derive(Eq, Debug)

///|
pub(all) struct PcapGlobalHeader {
  magic : PcapMagic
  endian : @binary.Endian
  version_major : UInt
  version_minor : UInt
  thiszone : Int
  sigfigs : UInt
  snaplen : UInt
  network : UInt // LinkType (1 = Ethernet, 105 = 802.11, etc.)
  is_nanosecond : Bool
} derive(Eq, Debug)

///|
pub fn parse_magic(reader : @binary.BinaryReader) -> PcapGlobalHeader? {
  if !reader.has_bytes(24) {
    return None
  }
  let pos = reader.tell()
  reader.set_endian(@binary.LittleEndian)
  let raw_magic = reader.read_u32()

  let (magic, endian, is_nano) = match raw_magic {
    0xA1B2C3D4U => (PcapMagic::MicrosecondBig, @binary.BigEndian, false)
    0xD4C3B2A1U => (PcapMagic::MicrosecondLittle, @binary.LittleEndian, false)
    0xA1B23C4DU => (PcapMagic::NanosecondBig, @binary.BigEndian, true)
    0x4D3CB2A1U => (PcapMagic::NanosecondLittle, @binary.LittleEndian, true)
    _ => {
      reader.seek(pos)
      return None
    }
  }

  reader.set_endian(endian)
  let version_major = reader.read_u16()
  let version_minor = reader.read_u16()
  let thiszone = reader.read_i32()
  let sigfigs = reader.read_u32()
  let snaplen = reader.read_u32()
  let network = reader.read_u32()

  Some({
    magic,
    endian,
    version_major,
    version_minor,
    thiszone,
    sigfigs,
    snaplen,
    network,
    is_nanosecond: is_nano,
  })
}
