// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/modbus.mbt

///|
pub(all) struct ModbusHeader {
  transaction_id : UInt
  protocol_id : UInt
  length : UInt
  unit_id : Byte
  function_code : Byte
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_modbus_tcp(data : Bytes) -> ModbusHeader? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(8) {
    return None
  }
  let transaction_id = reader.read_u16()
  let protocol_id = reader.read_u16()
  let length = reader.read_u16()
  let unit_id = reader.read_u8()
  let function_code = reader.read_u8()

  let rem_len = reader.remaining()
  let payload = reader.read_bytes(rem_len)

  Some({ transaction_id, protocol_id, length, unit_id, function_code, payload })
}
