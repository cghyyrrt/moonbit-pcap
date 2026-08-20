// Safe PCAPNG option construction helpers shared by writers and exporters.

///|
/// Create an option with a checked 16-bit code and length.
pub fn make_pcapng_option(code : UInt, value : Bytes) -> PcapngOption {
  let safe_code = code & 0xFFFFU
  let safe_length = value.length().reinterpret_as_uint() & 0xFFFFU
  { code: safe_code, length: safe_length, value }
}

///|
/// Create the end-of-options marker.
pub fn make_pcapng_end_option() -> PcapngOption {
  { code: 0U, length: 0U, value: Bytes::from_array([]) }
}

///|
/// Return true for the PCAPNG end-of-options marker.
pub fn is_pcapng_end_option(option : PcapngOption) -> Bool {
  option.code == 0U && option.length == 0U && option.value.length() == 0
}

///|
/// Return the four-byte padding required by an option value.
pub fn pcapng_option_padding(option : PcapngOption) -> Int {
  (4 - option.value.length() % 4) % 4
}

///|
/// Construct a UTF-8/ASCII text option from a string.
pub fn make_pcapng_text_option(code : UInt, text : String) -> PcapngOption {
  let bytes : Array[Byte] = []
  for c in text {
    bytes.push(c.to_int().to_byte())
  }
  make_pcapng_option(code, Bytes::from_array(bytes))
}

///|
/// Return printable option bytes as text, replacing non-printable bytes.
pub fn option_value_as_text(option : PcapngOption) -> String? {
  let chars : Array[Char] = []
  for byte in option.value {
    let value = byte.to_int()
    if value == 0 {
      break
    }
    if value >= 32 && value <= 126 {
      chars.push(value.unsafe_to_char())
    } else {
      chars.push('?')
    }
  }
  let builder = StringBuilder::new()
  for c in chars {
    builder.write_char(c)
  }
  Some(builder.to_string())
}

///|
/// Return whether an option's declared length agrees with its value.
pub fn is_pcapng_option_consistent(option : PcapngOption) -> Bool {
  option.length.reinterpret_as_int() == option.value.length()
}

///|
/// Return a copy with its declared length synchronized to the value.
pub fn normalize_pcapng_option(option : PcapngOption) -> PcapngOption {
  {
    code: option.code,
    length: option.value.length().reinterpret_as_uint(),
    value: option.value,
  }
}

///|
/// Return true if the option code is in the reserved end-marker range.
pub fn is_reserved_pcapng_option_code(code : UInt) -> Bool {
  code == 0U
}
