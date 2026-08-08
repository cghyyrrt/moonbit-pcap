// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcapng/isb.mbt

///|
pub(all) struct InterfaceStatsBlock {
  interface_id : UInt
  timestamp_high : UInt
  timestamp_low : UInt
  packets_received : UInt64
  packets_dropped : UInt64
  options : Array[PcapngOption]
} derive(Eq, Debug)

///|
pub fn parse_isb(
  reader : @binary.BinaryReader,
  total_len : Int,
) -> InterfaceStatsBlock? {
  if total_len < 24 || !reader.has_bytes(12) {
    return None
  }
  let interface_id = reader.read_u32()
  let ts_high = reader.read_u32()
  let ts_low = reader.read_u32()

  let opt_bytes_len = total_len - 24
  let options = if opt_bytes_len > 0 {
    parse_options(reader, opt_bytes_len)
  } else {
    Array::new()
  }

  let mut rx = 0UL
  let mut drop = 0UL

  for opt in options {
    if opt.code == 4U && opt.value.length() >= 8 { // isb_ifrecv
      let r = @binary.BinaryReader::new(opt.value, endian=reader.get_endian())
      rx = r.read_u64()
    } else if opt.code == 5U && opt.value.length() >= 8 { // isb_ifdrop
      let r = @binary.BinaryReader::new(opt.value, endian=reader.get_endian())
      drop = r.read_u64()
    }
  }

  Some({
    interface_id,
    timestamp_high: ts_high,
    timestamp_low: ts_low,
    packets_received: rx,
    packets_dropped: drop,
    options,
  })
}
