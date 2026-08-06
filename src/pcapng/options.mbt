// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcapng/options.mbt

///|
pub(all) struct PcapngOption {
  code : UInt
  length : UInt
  value : Bytes
} derive(Eq, Debug)

///|
pub fn parse_options(
  reader : @binary.BinaryReader,
  total_opt_len : Int,
) -> Array[PcapngOption] {
  let options = Array::new()
  let start_pos = reader.tell()
  let end_pos = start_pos + total_opt_len

  while reader.tell() < end_pos && reader.has_bytes(4) {
    let code = reader.read_u16()
    let length = reader.read_u16()
    let len_int = length.reinterpret_as_int()
    if code == 0U { // opt_endofopt
      // consume padding if any
      let rem = (4 - len_int % 4) % 4
      if rem > 0 && reader.has_bytes(rem) {
        reader.skip(rem)
      }
      break
    }
    if !reader.has_bytes(len_int) {
      break
    }
    let value = reader.read_bytes(len_int)
    let pad = (4 - len_int % 4) % 4
    if pad > 0 && reader.has_bytes(pad) {
      reader.skip(pad)
    }
    options.push({ code, length, value })
  }

  options
}

///|
pub fn find_option_string(
  options : Array[PcapngOption],
  target_code : UInt,
) -> String? {
  for opt in options {
    if opt.code == target_code {
      let arr : Array[Char] = Array::new()
      for i = 0; i < opt.value.length(); i = i + 1 {
        let b = opt.value[i].to_int()
        if b >= 32 && b <= 126 {
          arr.push(b.unsafe_to_char())
        }
      }
      let buf = StringBuilder::new()
      for c in arr {
        buf.write_char(c)
      }
      return Some(buf.to_string())
    }
  }
  None
}
