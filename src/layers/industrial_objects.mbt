// Common object-level decoders for EtherNet/IP CIP and DNP3 telemetry.

///|
pub(all) enum CipService {
  GetAttributeAll
  SetAttributeAll
  GetAttributeSingle
  SetAttributeSingle
  Reset
  Start
  Stop
  Create
  Delete
  ForwardOpen
  ForwardClose
  UnknownService(Byte)
} derive(Eq, Debug)

///|
pub(all) struct CipMessage {
  service : CipService
  service_code : Byte
  is_response : Bool
  path_words : Byte
  class_id : UInt?
  instance_id : UInt?
  attribute_id : UInt?
  status : Byte
  additional_status_size : Byte
  data : Bytes
} derive(Eq, Debug)

///|
fn cip_service(code : Byte) -> CipService {
  match code {
    b'\x01' => GetAttributeAll
    b'\x02' => SetAttributeAll
    b'\x03' => GetAttributeSingle
    b'\x04' => SetAttributeSingle
    b'\x05' => Reset
    b'\x06' => Start
    b'\x07' => Stop
    b'\x08' => Create
    b'\x09' => Delete
    b'\x54' => ForwardOpen
    b'\x4E' => ForwardClose
    _ => UnknownService(code)
  }
}

///|
fn cip_logical_value(data : Bytes, pos : Int, segment : Int) -> (UInt?, Int) {
  if pos >= data.length() || data[pos].to_int() != segment {
    (None, pos)
  } else if pos + 1 >= data.length() {
    (None, data.length())
  } else {
    let value = data[pos + 1].to_uint()
    (Some(value), pos + 2)
  }
}

///|
/// Parse a compact CIP service request/response message.
pub fn parse_cip(data : Bytes) -> CipMessage? {
  if data.length() < 2 {
    return None
  }
  let service_code = data[0]
  let is_response = (service_code.to_int() & 0x80) != 0
  let base_service = (service_code.to_int() & 0x7F).to_byte()
  let path_words = data[1]
  let path_len = path_words.to_int() * 2
  let path_end = 2 + path_len
  if path_end > data.length() {
    return None
  }
  let mut pos = 2
  let (class_id, next_class) = if is_response {
    (None, pos)
  } else {
    cip_logical_value(data, pos, 0x20)
  }
  pos = next_class
  let (instance_id, next_instance) = if is_response {
    (None, pos)
  } else {
    cip_logical_value(data, pos, 0x24)
  }
  pos = next_instance
  let (attribute_id, next_attribute) = if is_response {
    (None, pos)
  } else {
    cip_logical_value(data, pos, 0x30)
  }
  pos = next_attribute
  if !is_response && pos > path_end {
    return None
  }
  let status = if is_response && data.length() >= 4 { data[2] } else { b'\x00' }
  let additional_status_size = if is_response && data.length() >= 4 {
    data[3]
  } else {
    b'\x00'
  }
  let data_start = if is_response {
    4 + additional_status_size.to_int() * 2
  } else {
    path_end
  }
  if data_start > data.length() {
    return None
  }
  let payload = @binary.BinaryReader::new(data, offset=data_start).read_bytes(
    data.length() - data_start,
  )
  Some({
    service: cip_service(base_service),
    service_code,
    is_response,
    path_words,
    class_id,
    instance_id,
    attribute_id,
    status,
    additional_status_size,
    data: payload,
  })
}

///|
/// Return the conventional service name.
pub fn cip_service_name(service : CipService) -> String {
  match service {
    GetAttributeAll => "GetAttributeAll"
    SetAttributeAll => "SetAttributeAll"
    GetAttributeSingle => "GetAttributeSingle"
    SetAttributeSingle => "SetAttributeSingle"
    Reset => "Reset"
    Start => "Start"
    Stop => "Stop"
    Create => "Create"
    Delete => "Delete"
    ForwardOpen => "ForwardOpen"
    ForwardClose => "ForwardClose"
    UnknownService(code) => "UnknownService(\{code})"
  }
}

///|
/// Return whether a CIP response reports success.
pub fn CipMessage::is_success(self : CipMessage) -> Bool {
  self.is_response && self.status == b'\x00'
}

///|
/// Return a user-facing description for a CIP status byte.
pub fn cip_status_name(status : Byte) -> String {
  match status {
    b'\x00' => "Success"
    b'\x01' => "Connection failure"
    b'\x04' => "Path segment error"
    b'\x05' => "Path destination unknown"
    b'\x08' => "Service not supported"
    b'\x14' => "Attribute not supported"
    _ => "Unknown status"
  }
}

///|
pub(all) struct Dnp3BinaryValue {
  index : UInt
  value : Bool
  quality : Byte
} derive(Eq, Debug)

///|
pub(all) struct Dnp3AnalogValue {
  index : UInt
  value : Int
  quality : Byte
} derive(Eq, Debug)

///|
/// Decode one-byte indexed binary values with a quality byte.
pub fn parse_dnp3_binary_values(
  data : Bytes,
  start_index : UInt,
) -> Array[Dnp3BinaryValue]? {
  if data.length() == 0 || data.length() % 2 != 0 {
    return None
  }
  let values : Array[Dnp3BinaryValue] = []
  for i = 0; i < data.length(); i = i + 2 {
    values.push({
      index: start_index + (i / 2).reinterpret_as_uint(),
      value: (data[i].to_int() & 0x01) != 0,
      quality: data[i + 1],
    })
  }
  Some(values)
}

///|
/// Decode little-endian signed 16-bit analog values with a quality byte.
pub fn parse_dnp3_analog_values(
  data : Bytes,
  start_index : UInt,
) -> Array[Dnp3AnalogValue]? {
  if data.length() == 0 || data.length() % 4 != 0 {
    return None
  }
  let values : Array[Dnp3AnalogValue] = []
  for i = 0; i < data.length(); i = i + 4 {
    let raw = data[i].to_int() | (data[i + 1].to_int() << 8)
    let value = if raw >= 32768 { raw - 65536 } else { raw }
    values.push({
      index: start_index + (i / 4).reinterpret_as_uint(),
      value,
      quality: data[i + 2],
    })
  }
  Some(values)
}

///|
/// Return whether a DNP3 quality byte indicates an online value.
pub fn dnp3_quality_online(quality : Byte) -> Bool {
  (quality.to_int() & 0x01) != 0
}

///|
/// Return whether a DNP3 quality byte marks a value as comms lost.
pub fn dnp3_quality_comm_lost(quality : Byte) -> Bool {
  (quality.to_int() & 0x04) != 0
}

///|
/// Convert a DNP3 class mask to a stable human-readable label.
pub fn dnp3_class_name(class_mask : Byte) -> String {
  match class_mask.to_int() & 0x07 {
    0 => "Class 0"
    1 => "Class 1"
    2 => "Class 2"
    4 => "Class 3"
    _ => "Multiple classes"
  }
}
