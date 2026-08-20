// DNP3 link, transport, application, and object headers.

///|
pub(all) struct Dnp3LinkHeader {
  length : Byte
  control : Byte
  destination : UInt
  source : UInt
  header_crc : UInt
  crc_valid : Bool
  payload : Bytes
} derive(Eq, Debug)

///|
pub(all) struct Dnp3TransportHeader {
  final_fragment : Bool
  first_fragment : Bool
  sequence : Byte
  payload : Bytes
} derive(Eq, Debug)

///|
pub(all) struct Dnp3ApplicationHeader {
  final_fragment : Bool
  first_fragment : Bool
  confirm : Bool
  unsolicited : Bool
  sequence : Byte
  payload : Bytes
} derive(Eq, Debug)

///|
pub(all) struct Dnp3ObjectHeader {
  group : Byte
  variation : Byte
  qualifier : Byte
  count : UInt
} derive(Eq, Debug)

///|
pub(all) struct Dnp3Frame {
  link : Dnp3LinkHeader
  transport : Dnp3TransportHeader
  application : Dnp3ApplicationHeader
  objects : Array[Dnp3ObjectHeader]
  valid_length : Bool
} derive(Eq, Debug)

///|
fn dnp3_crc(data : Bytes, start : Int, length : Int) -> UInt {
  let mut crc = 0x0000U
  let end = if start + length > data.length() {
    data.length()
  } else {
    start + length
  }
  for i = start; i < end; i = i + 1 {
    crc = crc ^ data[i].to_uint()
    for j = 0; j < 8; j = j + 1 {
      if (crc & 1U) != 0U {
        crc = (crc >> 1) ^ 0xA6BCU
      } else {
        crc = crc >> 1
      }
    }
  }
  crc & 0xFFFFU
}

///|
fn dnp3_read_u16(data : Bytes, pos : Int) -> UInt {
  data[pos].to_uint() | (data[pos + 1].to_uint() << 8)
}

///|
fn dnp3_object_count(qualifier : Byte, data : Bytes, pos : Int) -> (UInt, Int) {
  match qualifier.to_int() & 0x0F {
    0x00 | 0x01 | 0x02 | 0x03 => (1U, pos)
    0x07 | 0x08 | 0x09 | 0x0A =>
      if pos + 1 < data.length() {
        (dnp3_read_u16(data, pos), pos + 2)
      } else {
        (0U, pos)
      }
    _ => (0U, pos)
  }
}

///|
/// Parse a DNP3 frame with bounded access and per-header CRC status.
pub fn parse_dnp3(data : Bytes) -> Dnp3Frame? {
  if data.length() < 10 || data[0] != b'\x05' || data[1] != b'\x64' {
    return None
  }
  let length = data[2]
  if length.to_int() < 5 || length.to_int() + 3 > data.length() {
    return None
  }
  let control = data[3]
  let destination = dnp3_read_u16(data, 4)
  let source = dnp3_read_u16(data, 6)
  let header_crc = dnp3_read_u16(data, 8)
  let expected_crc = dnp3_crc(data, 0, 8)
  let link_payload_start = 10
  let declared_payload_len = length.to_int() - 5
  let available_payload_len = data.length() - link_payload_start
  let payload_len = if declared_payload_len < available_payload_len {
    declared_payload_len
  } else {
    available_payload_len
  }
  if payload_len < 2 {
    return None
  }
  let link_payload = @binary.BinaryReader::new(data, offset=link_payload_start).read_bytes(
    payload_len,
  )
  let transport_byte = link_payload[0]
  let application_byte = link_payload[1]
  let transport = {
    final_fragment: (transport_byte.to_int() & 0x80) != 0,
    first_fragment: (transport_byte.to_int() & 0x40) != 0,
    sequence: (transport_byte.to_int() & 0x3F).to_byte(),
    payload: link_payload,
  }
  let application = {
    final_fragment: (application_byte.to_int() & 0x80) != 0,
    first_fragment: (application_byte.to_int() & 0x40) != 0,
    confirm: (application_byte.to_int() & 0x20) != 0,
    unsolicited: (application_byte.to_int() & 0x10) != 0,
    sequence: (application_byte.to_int() & 0x0F).to_byte(),
    payload: link_payload,
  }
  let objects : Array[Dnp3ObjectHeader] = []
  if payload_len >= 6 {
    let group = link_payload[2]
    let variation = link_payload[3]
    let qualifier = link_payload[4]
    let (count, _) = dnp3_object_count(qualifier, link_payload, 5)
    objects.push({ group, variation, qualifier, count })
  }
  Some({
    link: {
      length,
      control,
      destination,
      source,
      header_crc,
      crc_valid: expected_crc == header_crc,
      payload: link_payload,
    },
    transport,
    application,
    objects,
    valid_length: length.to_int() + 3 == data.length(),
  })
}

///|
/// Return a descriptive name for common DNP3 object groups.
pub fn dnp3_object_group_name(group : Byte) -> String {
  match group {
    b'\x01' => "Binary Input"
    b'\x02' => "Binary Input Event"
    b'\x0A' => "Binary Output"
    b'\x14' => "Frozen Counter"
    b'\x1E' => "Analog Input"
    b'\x20' => "Counter"
    _ => "Unknown Object Group"
  }
}

///|
/// Return whether all length constraints in the frame were satisfied.
pub fn Dnp3Frame::is_well_formed(self : Dnp3Frame) -> Bool {
  self.valid_length && self.link.payload.length() >= 2
}
