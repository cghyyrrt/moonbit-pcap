// Stable industrial function and object metadata for reports and tooling.

///|
pub(all) enum Dnp3FunctionCode {
  Confirm
  Read
  Write
  Select
  Operate
  DirectOperate
  DirectOperateNoAck
  ImmediateFreeze
  FreezeClear
  FreezeAtTime
  ColdRestart
  WarmRestart
  InitializeData
  InitializeApplication
  StartApplication
  StopApplication
  SaveConfiguration
  EnableUnsolicited
  DisableUnsolicited
  AssignClass
  DelayMeasure
  RecordCurrentTime
  OpenFile
  CloseFile
  UnknownFunction(Byte)
} derive(Eq, Debug)

///|
/// Map a DNP3 application function byte to a named operation.
pub fn dnp3_function(code : Byte) -> Dnp3FunctionCode {
  match code {
    b'\x00' => Confirm
    b'\x01' => Read
    b'\x02' => Write
    b'\x03' => Select
    b'\x04' => Operate
    b'\x05' => DirectOperate
    b'\x06' => DirectOperateNoAck
    b'\x07' => ImmediateFreeze
    b'\x08' => FreezeClear
    b'\x09' => FreezeAtTime
    b'\x0D' => ColdRestart
    b'\x0E' => WarmRestart
    b'\x0F' => InitializeData
    b'\x10' => InitializeApplication
    b'\x11' => StartApplication
    b'\x12' => StopApplication
    b'\x13' => SaveConfiguration
    b'\x14' => EnableUnsolicited
    b'\x15' => DisableUnsolicited
    b'\x16' => AssignClass
    b'\x17' => DelayMeasure
    b'\x18' => RecordCurrentTime
    b'\x19' => OpenFile
    b'\x1A' => CloseFile
    _ => UnknownFunction(code)
  }
}

///|
/// Return a display name for a DNP3 application function.
pub fn dnp3_function_name(function : Dnp3FunctionCode) -> String {
  match function {
    Confirm => "Confirm"
    Read => "Read"
    Write => "Write"
    Select => "Select"
    Operate => "Operate"
    DirectOperate => "Direct Operate"
    DirectOperateNoAck => "Direct Operate No Ack"
    ImmediateFreeze => "Immediate Freeze"
    FreezeClear => "Freeze and Clear"
    FreezeAtTime => "Freeze at Time"
    ColdRestart => "Cold Restart"
    WarmRestart => "Warm Restart"
    InitializeData => "Initialize Data"
    InitializeApplication => "Initialize Application"
    StartApplication => "Start Application"
    StopApplication => "Stop Application"
    SaveConfiguration => "Save Configuration"
    EnableUnsolicited => "Enable Unsolicited"
    DisableUnsolicited => "Disable Unsolicited"
    AssignClass => "Assign Class"
    DelayMeasure => "Delay Measure"
    RecordCurrentTime => "Record Current Time"
    OpenFile => "Open File"
    CloseFile => "Close File"
    UnknownFunction(code) => "Unknown(\{code.to_int()})"
  }
}

///|
/// Return whether the function only reads remote state.
pub fn dnp3_function_is_read(function : Dnp3FunctionCode) -> Bool {
  function is Read || function is Confirm
}

///|
/// Return whether the function changes remote state.
pub fn dnp3_function_is_write(function : Dnp3FunctionCode) -> Bool {
  function is Write ||
  function is Select ||
  function is Operate ||
  function is DirectOperate ||
  function is DirectOperateNoAck
}

///|
/// Encode a CIP logical class/instance/attribute path using 8-bit segments.
pub fn encode_cip_logical_path(
  class_id : UInt,
  instance_id : UInt,
  attribute_id : UInt?,
) -> Bytes {
  let bytes : Array[Byte] = [
    b'\x20',
    class_id.to_byte(),
    b'\x24',
    instance_id.to_byte(),
  ]
  match attribute_id {
    Some(attribute) => {
      bytes.push(b'\x30')
      bytes.push(attribute.to_byte())
    }
    None => ()
  }
  Bytes::from_array(bytes)
}

///|
/// Return the number of 16-bit words occupied by a CIP path.
pub fn cip_path_word_count(path : Bytes) -> Int {
  (path.length() + 1) / 2
}

///|
/// Return the encoded width of common DNP3 object values.
pub fn dnp3_object_value_width(group : UInt, variation : UInt) -> Int {
  match (group, variation) {
    (1U, 1U) | (1U, 2U) | (2U, 1U) => 1
    (30U, 1U) | (30U, 2U) | (32U, 1U) => 2
    (30U, 3U) | (30U, 4U) | (32U, 3U) => 4
    (30U, 5U) | (30U, 6U) => 4
    (20U, 1U) | (20U, 2U) => 4
    _ => 0
  }
}

///|
/// Return whether a DNP3 object group represents a binary state.
pub fn dnp3_is_binary_group(group : UInt) -> Bool {
  group == 1U || group == 2U || group == 10U || group == 11U
}

///|
/// Return whether a DNP3 object group represents an analog measurement.
pub fn dnp3_is_analog_group(group : UInt) -> Bool {
  group == 30U || group == 32U || group == 40U || group == 42U
}

///|
/// Return whether a CIP service code is a request code.
pub fn cip_is_request_code(code : Byte) -> Bool {
  (code.to_int() & 0x80) == 0
}

///|
/// Return the response code corresponding to a CIP request code.
pub fn cip_response_code(code : Byte) -> Byte {
  (code.to_int() | 0x80).to_byte()
}
