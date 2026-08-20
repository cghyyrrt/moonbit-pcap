// EtherNet/IP encapsulation header and common session commands.

///|
pub(all) enum EthernetIpCommand {
  NoOperation
  ListServices
  ListIdentity
  ListInterfaces
  RegisterSession
  UnregisterSession
  SendRRData
  SendUnitData
  Unknown(UInt)
} derive(Eq, Debug)

///|
pub(all) struct EthernetIpEncapsulation {
  command : EthernetIpCommand
  command_code : UInt
  length : UInt
  session_handle : UInt
  status : UInt
  sender_context : UInt64
  options : UInt
  payload : Bytes
  valid_length : Bool
} derive(Eq, Debug)

///|
fn ethernet_ip_command(code : UInt) -> EthernetIpCommand {
  match code {
    0x0000U => NoOperation
    0x0004U => ListServices
    0x0063U => ListIdentity
    0x0064U => ListInterfaces
    0x0065U => RegisterSession
    0x0066U => UnregisterSession
    0x006FU => SendRRData
    0x0070U => SendUnitData
    _ => Unknown(code)
  }
}

///|
/// Parse a 24-byte little-endian EtherNet/IP encapsulation frame.
pub fn parse_ethernet_ip(data : Bytes) -> EthernetIpEncapsulation? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.LittleEndian)
  if !reader.has_bytes(24) {
    return None
  }
  let command_code = reader.read_u16()
  let length = reader.read_u16()
  let session_handle = reader.read_u32()
  let status = reader.read_u32()
  let sender_context = reader.read_u64()
  let options = reader.read_u32()
  let payload_len = length.reinterpret_as_int()
  if payload_len > reader.remaining() {
    return None
  }
  let payload = reader.read_bytes(payload_len)
  Some({
    command: ethernet_ip_command(command_code),
    command_code,
    length,
    session_handle,
    status,
    sender_context,
    options,
    payload,
    valid_length: payload_len == data.length() - 24,
  })
}

///|
/// Return the command's conventional EtherNet/IP name.
pub fn ethernet_ip_command_name(command : EthernetIpCommand) -> String {
  match command {
    NoOperation => "NoOperation"
    ListServices => "ListServices"
    ListIdentity => "ListIdentity"
    ListInterfaces => "ListInterfaces"
    RegisterSession => "RegisterSession"
    UnregisterSession => "UnregisterSession"
    SendRRData => "SendRRData"
    SendUnitData => "SendUnitData"
    Unknown(code) => "Unknown(\{code})"
  }
}

///|
/// Return true when the declared payload consumes the complete input.
pub fn EthernetIpEncapsulation::is_well_formed(
  self : EthernetIpEncapsulation,
) -> Bool {
  self.valid_length
}

///|
/// Parse the two-word RegisterSession payload.
pub fn EthernetIpEncapsulation::register_session_version(
  self : EthernetIpEncapsulation,
) -> UInt? {
  match self.command {
    RegisterSession =>
      if self.payload.length() >= 2 {
        Some(self.payload[0].to_uint() | (self.payload[1].to_uint() << 8))
      } else {
        None
      }
    _ => None
  }
}

///|
/// Parse the two-word RegisterSession option field.
pub fn EthernetIpEncapsulation::register_session_options(
  self : EthernetIpEncapsulation,
) -> UInt? {
  match self.command {
    RegisterSession =>
      if self.payload.length() >= 4 {
        Some(self.payload[2].to_uint() | (self.payload[3].to_uint() << 8))
      } else {
        None
      }
    _ => None
  }
}
