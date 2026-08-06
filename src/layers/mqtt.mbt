// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/mqtt.mbt

///|
pub(all) struct MqttFixedHeader {
  packet_type : Byte
  flags : Byte
  remaining_length : UInt
} derive(Eq, Debug)

///|
pub(all) struct MqttPacket {
  header : MqttFixedHeader
  topic : String?
  payload : Bytes
} derive(Eq, Debug)

///|
pub fn parse_mqtt(data : Bytes) -> MqttPacket? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(2) {
    return None
  }
  let b0 = reader.read_u8().to_int()
  let packet_type = ((b0 >> 4) & 0x0F).to_byte()
  let flags = (b0 & 0x0F).to_byte()

  // Decode Variable Byte Integer remaining length
  let mut multiplier = 1U
  let mut rem_len = 0U
  let mut digit = 0
  let mut count = 0

  while count < 4 && reader.has_bytes(1) {
    digit = reader.read_u8().to_int()
    let val = (digit & 0x7F).reinterpret_as_uint()
    rem_len = rem_len + val * multiplier
    if (digit & 0x80) == 0 {
      break
    }
    multiplier = multiplier * 128U
    count = count + 1
  }

  let header = { packet_type, flags, remaining_length: rem_len }
  let mut topic : String? = None

  if packet_type == b'\x03' && reader.has_bytes(2) { // PUBLISH
    let topic_len = reader.read_u16().reinterpret_as_int()
    if reader.has_bytes(topic_len) {
      let t_bytes = reader.read_bytes(topic_len)
      let buf = StringBuilder::new()
      for i = 0; i < topic_len; i = i + 1 {
        let b = t_bytes[i].to_int()
        if b >= 32 && b <= 126 {
          buf.write_char(b.unsafe_to_char())
        }
      }
      topic = Some(buf.to_string())
    }
  }

  let payload_rem = reader.remaining()
  let payload = if payload_rem > 0 {
    reader.read_bytes(payload_rem)
  } else {
    Bytes::from_array([])
  }

  Some({ header, topic, payload })
}
