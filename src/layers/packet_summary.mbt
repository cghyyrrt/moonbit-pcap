// Fast, allocation-light packet classification for dashboards and CLI output.

///|
pub(all) struct PacketSummary {
  link : String
  network : String
  transport : String
  src_port : UInt
  dst_port : UInt
  payload_length : Int
  malformed : Bool
} derive(Eq, Debug)

///|
fn packet_transport_name(protocol : Byte) -> String {
  match protocol {
    b'\x01' => "ICMP"
    b'\x06' => "TCP"
    b'\x11' => "UDP"
    b'\x84' => "SCTP"
    _ => "Unknown"
  }
}

///|
fn packet_ports(payload : Bytes, transport : String) -> (UInt, UInt, Bool) {
  if (transport == "TCP" || transport == "UDP" || transport == "SCTP") &&
    payload.length() >= 4 {
    let src = (payload[0].to_uint() << 8) | payload[1].to_uint()
    let dst = (payload[2].to_uint() << 8) | payload[3].to_uint()
    (src, dst, false)
  } else {
    (0U, 0U, transport == "Unknown")
  }
}

///|
/// Summarize the outer Ethernet, IP, and transport layers.
pub fn summarize_packet(data : Bytes) -> PacketSummary? {
  match parse_ethernet(data) {
    None => None
    Some(ethernet) =>
      if ethernet.ethertype == 0x0800U {
        match parse_ipv4(ethernet.payload) {
          None =>
            Some({
              link: "Ethernet",
              network: "IPv4",
              transport: "Unknown",
              src_port: 0U,
              dst_port: 0U,
              payload_length: 0,
              malformed: true,
            })
          Some(ip) => {
            let transport = packet_transport_name(ip.protocol)
            let (src_port, dst_port, port_malformed) = packet_ports(
              ip.payload,
              transport,
            )
            Some({
              link: "Ethernet",
              network: "IPv4",
              transport,
              src_port,
              dst_port,
              payload_length: ip.payload.length(),
              malformed: port_malformed || !ip.is_checksum_valid,
            })
          }
        }
      } else if ethernet.ethertype == 0x86DDU {
        match parse_ipv6(ethernet.payload) {
          None =>
            Some({
              link: "Ethernet",
              network: "IPv6",
              transport: "Unknown",
              src_port: 0U,
              dst_port: 0U,
              payload_length: 0,
              malformed: true,
            })
          Some(ip) => {
            let transport = packet_transport_name(ip.next_header)
            let (src_port, dst_port, port_malformed) = packet_ports(
              ip.payload,
              transport,
            )
            Some({
              link: "Ethernet",
              network: "IPv6",
              transport,
              src_port,
              dst_port,
              payload_length: ip.payload.length(),
              malformed: port_malformed,
            })
          }
        }
      } else {
        Some({
          link: "Ethernet",
          network: "Unknown",
          transport: "Unknown",
          src_port: 0U,
          dst_port: 0U,
          payload_length: ethernet.payload.length(),
          malformed: ethernet.payload.length() == 0,
        })
      }
  }
}

///|
/// Return a concise protocol path such as `Ethernet/IPv4/TCP`.
pub fn PacketSummary::protocol_path(self : PacketSummary) -> String {
  "\{self.link}/\{self.network}/\{self.transport}"
}

///|
/// Return true when the summary contains a malformed inner header.
pub fn PacketSummary::is_malformed(self : PacketSummary) -> Bool {
  self.malformed
}
