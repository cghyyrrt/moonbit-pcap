// Central application-protocol naming and port classification.

///|
pub(all) enum ApplicationProtocol {
  HTTP
  DNS
  ModbusTCP
  MQTT
  CoAP
  EtherNetIP
  DNP3
  SSH
  TLS
  UnknownApplication(UInt)
} derive(Eq, Debug)

///|
/// Classify a TCP/UDP service port without inspecting packet bytes.
pub fn classify_application_port(port : UInt) -> ApplicationProtocol {
  match port {
    80U | 8080U => HTTP
    53U => DNS
    502U => ModbusTCP
    1883U | 8883U => MQTT
    5683U | 5684U => CoAP
    44818U => EtherNetIP
    20000U => DNP3
    22U => SSH
    443U | 853U => TLS
    _ => UnknownApplication(port)
  }
}

///|
/// Use a port first and a bounded signature check second.
pub fn classify_application_payload(
  port : UInt,
  payload : Bytes,
) -> ApplicationProtocol {
  match classify_application_port(port) {
    UnknownApplication(_) =>
      if payload.length() >= 4 &&
        payload[0] == b'G' &&
        payload[1] == b'E' &&
        payload[2] == b'T' &&
        payload[3] == b' ' {
        HTTP
      } else if payload.length() >= 2 && payload[0] == b'\x10' {
        MQTT
      } else if payload.length() >= 4 &&
        payload[0] == b'\x05' &&
        payload[1] == b'\x64' {
        DNP3
      } else {
        UnknownApplication(port)
      }
    known => known
  }
}

///|
/// Return a stable protocol label for reports and filters.
pub fn application_protocol_name(protocol : ApplicationProtocol) -> String {
  match protocol {
    HTTP => "HTTP"
    DNS => "DNS"
    ModbusTCP => "Modbus TCP"
    MQTT => "MQTT"
    CoAP => "CoAP"
    EtherNetIP => "EtherNet/IP"
    DNP3 => "DNP3"
    SSH => "SSH"
    TLS => "TLS"
    UnknownApplication(port) => "Unknown(\{port})"
  }
}

///|
/// Return whether a protocol belongs to the industrial analysis group.
pub fn is_industrial_application(protocol : ApplicationProtocol) -> Bool {
  protocol is ModbusTCP || protocol is EtherNetIP || protocol is DNP3
}

///|
/// Return whether a protocol is encrypted by convention.
pub fn is_encrypted_application(protocol : ApplicationProtocol) -> Bool {
  protocol is TLS || protocol is SSH || (protocol is CoAP && false)
}

///|
/// Return the conventional default port for a protocol.
pub fn default_application_port(protocol : ApplicationProtocol) -> UInt {
  match protocol {
    HTTP => 80U
    DNS => 53U
    ModbusTCP => 502U
    MQTT => 1883U
    CoAP => 5683U
    EtherNetIP => 44818U
    DNP3 => 20000U
    SSH => 22U
    TLS => 443U
    UnknownApplication(port) => port
  }
}

///|
/// Return whether the protocol is conventionally carried over UDP.
pub fn is_udp_application(protocol : ApplicationProtocol) -> Bool {
  protocol is DNS || protocol is CoAP || protocol is DNP3
}

///|
/// Return whether a protocol can be identified without a transport port.
pub fn has_payload_signature(protocol : ApplicationProtocol) -> Bool {
  protocol is HTTP || protocol is MQTT || protocol is DNP3
}

///|
/// Return whether the protocol normally carries request/response exchanges.
pub fn is_request_response_application(protocol : ApplicationProtocol) -> Bool {
  protocol is HTTP ||
  protocol is DNS ||
  protocol is ModbusTCP ||
  protocol is EtherNetIP ||
  protocol is DNP3
}

///|
/// Return whether a protocol is commonly used for telemetry collection.
pub fn is_telemetry_application(protocol : ApplicationProtocol) -> Bool {
  protocol is DNS ||
  protocol is MQTT ||
  protocol is DNP3 ||
  protocol is ModbusTCP
}

///|
/// Return whether a protocol is commonly used for control commands.
pub fn is_control_application(protocol : ApplicationProtocol) -> Bool {
  protocol is EtherNetIP || protocol is ModbusTCP || protocol is DNP3
}
