// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/dns_ext.mbt

///|
pub(all) struct EdnsOption {
  code : UInt
  length : UInt
  data : Bytes
} derive(Eq, Debug)

///|
pub(all) struct OptResourceRecord {
  udp_payload_size : UInt
  extended_rcode : Byte
  version : Byte
  do_flag : Bool
  options : Array[EdnsOption]
} derive(Eq, Debug)

///|
pub fn parse_edns0_opt(rr : DnsResourceRecord) -> OptResourceRecord? {
  if rr.rtype != 41U { // OPT RR
    return None
  }
  let udp_payload_size = rr.rclass
  let ttl_val = rr.ttl
  let ext_rcode = ((ttl_val >> 24) & 0xFFU).reinterpret_as_int().to_byte()
  let version = ((ttl_val >> 16) & 0xFFU).reinterpret_as_int().to_byte()
  let do_flag = ((ttl_val >> 15) & 0x01U) != 0U

  let options = Array::new()
  let reader = @binary.BinaryReader::new(rr.rdata, endian=@binary.BigEndian)
  while reader.has_bytes(4) {
    let code = reader.read_u16()
    let length = reader.read_u16()
    let len_int = length.reinterpret_as_int()
    let opt_data = if reader.has_bytes(len_int) {
      reader.read_bytes(len_int)
    } else {
      Bytes::from_array([])
    }
    options.push({ code, length, data: opt_data })
  }

  Some({
    udp_payload_size,
    extended_rcode: ext_rcode,
    version,
    do_flag,
    options,
  })
}

///|
pub(all) struct DnssecKey {
  flags : UInt
  protocol : Byte
  algorithm : Byte
  public_key : Bytes
} derive(Eq, Debug)

///|
pub fn parse_dnskey_rdata(rdata : Bytes) -> DnssecKey? {
  let reader = @binary.BinaryReader::new(rdata, endian=@binary.BigEndian)
  if !reader.has_bytes(4) {
    return None
  }
  let flags = reader.read_u16()
  let protocol = reader.read_u8()
  let algorithm = reader.read_u8()

  let rem_len = reader.remaining()
  let public_key = reader.read_bytes(rem_len)

  Some({ flags, protocol, algorithm, public_key })
}
