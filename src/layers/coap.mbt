// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/coap.mbt

///|
pub(all) struct CoapHeader {
  version : Byte
  msg_type : Byte // 0 = CON, 1 = NON, 2 = ACK, 3 = RST
  token_length : Byte
  code : Byte // Method / Response Code
  message_id : UInt
  token : Bytes
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn get_coap_type_name(t : Byte) -> String {
  match t {
    b'\x00' => "Confirmable (CON)"
    b'\x01' => "Non-confirmable (NON)"
    b'\x02' => "Acknowledgement (ACK)"
    b'\x03' => "Reset (RST)"
    _ => "Unknown CoAP Type"
  }
}

///|
pub fn parse_coap(data : Bytes) -> CoapHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(4) {
    return None
  }
  let b0 = reader.read_u8().to_int()
  let version = ((b0 >> 6) & 0x03).to_byte()
  let msg_type = ((b0 >> 4) & 0x03).to_byte()
  let token_length = (b0 & 0x0F).to_byte()

  let code = reader.read_u8()
  let message_id = reader.read_u16()

  let t_len = token_length.to_int()
  let token = if t_len > 0 && reader.has_bytes(t_len) {
    reader.read_bytes(t_len)
  } else {
    Bytes::from_array([])
  }

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)

  Some({ version, msg_type, token_length, code, message_id, token, payload })
}
