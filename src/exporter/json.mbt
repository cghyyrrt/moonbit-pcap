// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: exporter/json.mbt

///|
pub fn export_stats_json(stats : @analyzer.TrafficStats) -> String {
  let dist = stats.get_protocol_distribution()
  let hist = stats.get_length_histogram()
  let total_p = stats.get_total_packets()
  let total_b = stats.get_total_bytes()
  let avg_l = stats.get_avg_length()
  let min_l = stats.get_min_len()
  let max_l = stats.get_max_len()

  let buf = StringBuilder::new()
  buf.write_string("{\n")
  buf.write_string("  \"total_packets\": \{total_p},\n")
  buf.write_string("  \"total_bytes\": \{total_b},\n")
  buf.write_string("  \"min_packet_length\": \{min_l},\n")
  buf.write_string("  \"max_packet_length\": \{max_l},\n")
  buf.write_string("  \"avg_packet_length\": \{avg_l},\n")
  buf.write_string("  \"protocols\": {\n")
  buf.write_string("    \"ethernet\": \{dist.eth_count},\n")
  buf.write_string("    \"arp\": \{dist.arp_count},\n")
  buf.write_string("    \"ipv4\": \{dist.ip4_count},\n")
  buf.write_string("    \"ipv6\": \{dist.ip6_count},\n")
  buf.write_string("    \"icmp\": \{dist.icmp_count},\n")
  buf.write_string("    \"tcp\": \{dist.tcp_count},\n")
  buf.write_string("    \"udp\": \{dist.udp_count},\n")
  buf.write_string("    \"dns\": \{dist.dns_count},\n")
  buf.write_string("    \"can\": \{dist.can_count},\n")
  buf.write_string("    \"modbus\": \{dist.modbus_count},\n")
  buf.write_string("    \"mqtt\": \{dist.mqtt_count}\n")
  buf.write_string("  },\n")
  buf.write_string("  \"length_histogram\": {\n")
  buf.write_string("    \"0_64\": \{hist.bucket_0_64},\n")
  buf.write_string("    \"65_128\": \{hist.bucket_65_128},\n")
  buf.write_string("    \"129_512\": \{hist.bucket_129_512},\n")
  buf.write_string("    \"513_1024\": \{hist.bucket_513_1024},\n")
  buf.write_string("    \"1025_1500\": \{hist.bucket_1025_1500},\n")
  buf.write_string("    \"jumbo\": \{hist.bucket_jumbo}\n")
  buf.write_string("  }\n")
  buf.write_string("}")
  buf.to_string()
}

///|
pub fn export_packet_json(pkt : @pcap.PcapPacket, idx : Int) -> String {
  let buf = StringBuilder::new()
  let hex_payload = @binary.bytes_to_hex(pkt.payload)
  buf.write_string("{\n")
  buf.write_string("  \"index\": \{idx},\n")
  buf.write_string("  \"timestamp_sec\": \{pkt.header.ts_sec},\n")
  buf.write_string("  \"timestamp_usec\": \{pkt.header.ts_usec},\n")
  buf.write_string("  \"captured_len\": \{pkt.header.incl_len},\n")
  buf.write_string("  \"original_len\": \{pkt.header.orig_len},\n")
  buf.write_string("  \"payload_hex\": \"\{hex_payload}\"\n")
  buf.write_string("}")
  buf.to_string()
}
