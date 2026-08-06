// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: exporter/text.mbt

///|
pub fn export_terminal_summary(
  stats : @analyzer.TrafficStats,
  anomalies : Array[@analyzer.NetworkAnomaly],
) -> String {
  let buf = StringBuilder::new()
  buf.write_string(
    "=========================================================\n",
  )
  buf.write_string(
    "           MoonBit Network Packet Analysis Summary       \n",
  )
  buf.write_string(
    "=========================================================\n",
  )
  buf.write_string("Total Packets Captured: \{stats.get_total_packets()}\n")
  buf.write_string("Total Volume:           \{stats.get_total_bytes()} bytes\n")
  buf.write_string("Min Packet Length:      \{stats.get_min_len()} bytes\n")
  buf.write_string("Max Packet Length:      \{stats.get_max_len()} bytes\n")
  buf.write_string(
    "Avg Packet Length:      \{stats.get_avg_length()} bytes\n\n",
  )

  let dist = stats.get_protocol_distribution()
  buf.write_string("--- Protocol Distribution ---\n")
  buf.write_string("  Ethernet : \{dist.eth_count}\n")
  buf.write_string("  ARP      : \{dist.arp_count}\n")
  buf.write_string("  IPv4     : \{dist.ip4_count}\n")
  buf.write_string("  IPv6     : \{dist.ip6_count}\n")
  buf.write_string("  ICMP     : \{dist.icmp_count}\n")
  buf.write_string("  TCP      : \{dist.tcp_count}\n")
  buf.write_string("  UDP      : \{dist.udp_count}\n")
  buf.write_string("  DNS      : \{dist.dns_count}\n")
  buf.write_string("  CAN      : \{dist.can_count}\n")
  buf.write_string("  Modbus   : \{dist.modbus_count}\n")
  buf.write_string("  MQTT     : \{dist.mqtt_count}\n\n")

  let hist = stats.get_length_histogram()
  buf.write_string("--- Packet Length Distribution ---\n")
  buf.write_string("  0-64 B     : \{hist.bucket_0_64}\n")
  buf.write_string("  65-128 B   : \{hist.bucket_65_128}\n")
  buf.write_string("  129-512 B  : \{hist.bucket_129_512}\n")
  buf.write_string("  513-1024 B : \{hist.bucket_513_1024}\n")
  buf.write_string("  1025-1500 B: \{hist.bucket_1025_1500}\n")
  buf.write_string("  Jumbo (>1.5K): \{hist.bucket_jumbo}\n\n")

  buf.write_string("--- Security & Anomaly Report ---\n")
  if anomalies.length() == 0 {
    buf.write_string("  No security anomalies detected.\n")
  } else {
    for a in anomalies {
      buf.write_string(
        "  [!] Packet #\{a.packet_idx} | Kind: \{a.kind} | Desc: \{a.description}\n",
      )
    }
  }
  buf.write_string(
    "=========================================================\n",
  )
  buf.to_string()
}
