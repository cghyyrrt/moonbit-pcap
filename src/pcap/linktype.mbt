// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcap/linktype.mbt

///|
pub(all) enum LinkType {
  Null
  Ethernet
  AX25
  IEEE802_5
  ARCNET
  SLIP
  PPP
  FDDI
  RawIP
  BSD_Loopback
  Linux_SLL
  IEEE802_11
  Linux_SLL2
  Bluetooth_HCI
  CAN_SocketCAN
  Unknown(UInt)
} derive(Eq, Debug)

///|
pub fn parse_linktype(code : UInt) -> LinkType {
  match code {
    0U => LinkType::Null
    1U => LinkType::Ethernet
    3U => LinkType::AX25
    6U => LinkType::IEEE802_5
    7U => LinkType::ARCNET
    8U => LinkType::SLIP
    9U => LinkType::PPP
    10U => LinkType::FDDI
    12U => LinkType::RawIP
    108U => LinkType::BSD_Loopback
    113U => LinkType::Linux_SLL
    127U => LinkType::IEEE802_11
    227U => LinkType::CAN_SocketCAN
    276U => LinkType::Linux_SLL2
    _ => LinkType::Unknown(code)
  }
}

///|
pub fn LinkType::to_string(self : LinkType) -> String {
  match self {
    Null => "BSD Loopback / Null"
    Ethernet => "Ethernet (10/100/1000 Mbps)"
    AX25 => "Amateur Radio AX.25"
    IEEE802_5 => "Token Ring (IEEE 802.5)"
    ARCNET => "ARCNET"
    SLIP => "Serial Line IP (SLIP)"
    PPP => "Point-to-Point Protocol (PPP)"
    FDDI => "FDDI"
    RawIP => "Raw IPv4 / IPv6"
    BSD_Loopback => "BSD Loopback"
    Linux_SLL => "Linux Cooked Capture v1 (SLL)"
    IEEE802_11 => "IEEE 802.11 Wireless LAN"
    Linux_SLL2 => "Linux Cooked Capture v2 (SLL2)"
    Bluetooth_HCI => "Bluetooth HCI UART"
    CAN_SocketCAN => "SocketCAN"
    Unknown(val) => "Unknown LinkType (\{val})"
  }
}
