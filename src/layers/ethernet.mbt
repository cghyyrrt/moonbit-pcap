// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/ethernet.mbt

///|
pub(all) struct VlanTag {
  tpid : UInt
  pcp : Byte
  dei : Bool
  vid : UInt
} derive(Eq, Debug)

///|
pub(all) struct EthernetHeader {
  dst_mac : Bytes
  src_mac : Bytes
  ethertype : UInt
  vlan_tags : Array[VlanTag]
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_ethernet(data : Bytes) -> EthernetHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(14) {
    return None
  }
  let dst_mac = reader.read_bytes(6)
  let src_mac = reader.read_bytes(6)
  let mut ethertype = reader.read_u16()

  let vlan_tags = Array::new()

  // Traversal for 802.1Q (0x8100) or 802.1ad (0x88A8 / 0x9100) QinQ tagging
  while ethertype == 0x8100U || ethertype == 0x88A8U || ethertype == 0x9100U {
    if !reader.has_bytes(4) {
      break
    }
    let tci = reader.read_u16()
    let pcp = ((tci >> 13) & 0x07U).reinterpret_as_int().to_byte()
    let dei = ((tci >> 12) & 0x01U) != 0U
    let vid = tci & 0x0FFFU
    vlan_tags.push({ tpid: ethertype, pcp, dei, vid })
    ethertype = reader.read_u16()
  }

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)

  Some({ dst_mac, src_mac, ethertype, vlan_tags, payload })
}
