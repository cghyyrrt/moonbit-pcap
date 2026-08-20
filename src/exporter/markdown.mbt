// Plain Markdown export for code review, issue reports, and static sites.

///|
pub fn markdown_escape(value : String) -> String {
  let builder = StringBuilder::new()
  for c in value {
    match c {
      '|' => builder.write_string("\\|")
      '\n' | '\r' => builder.write_char(' ')
      _ => builder.write_char(c)
    }
  }
  builder.to_string()
}

///|
fn markdown_anomaly_severity(severity : @analyzer.AnomalySeverity) -> String {
  match severity {
    @analyzer.Low => "low"
    @analyzer.Medium => "medium"
    @analyzer.High => "high"
    @analyzer.Critical => "critical"
  }
}

///|
/// Export traffic statistics and anomalies as portable Markdown.
pub fn export_markdown_report(
  stats : @analyzer.TrafficStats,
  anomalies : Array[@analyzer.NetworkAnomaly],
) -> String {
  let dist = stats.get_protocol_distribution()
  let hist = stats.get_length_histogram()
  let builder = StringBuilder::new()
  builder.write_string("# Network Packet Analysis Report\n\n")
  builder.write_string("## Overview\n\n")
  builder.write_string("| Metric | Value |\n| --- | ---: |\n")
  builder.write_string("| Packets | \{stats.get_total_packets()} |\n")
  builder.write_string("| Bytes | \{stats.get_total_bytes()} |\n")
  builder.write_string("| Minimum packet | \{stats.get_min_len()} |\n")
  builder.write_string("| Maximum packet | \{stats.get_max_len()} |\n")
  builder.write_string("| Average packet | \{stats.get_avg_length()} |\n\n")
  builder.write_string("## Protocol distribution\n\n")
  builder.write_string("| Protocol | Packets |\n| --- | ---: |\n")
  builder.write_string("| Ethernet | \{dist.eth_count} |\n")
  builder.write_string("| IPv4 | \{dist.ip4_count} |\n")
  builder.write_string("| IPv6 | \{dist.ip6_count} |\n")
  builder.write_string("| TCP | \{dist.tcp_count} |\n")
  builder.write_string("| UDP | \{dist.udp_count} |\n")
  builder.write_string("| DNS | \{dist.dns_count} |\n")
  builder.write_string("| Modbus TCP | \{dist.modbus_count} |\n")
  builder.write_string("| MQTT | \{dist.mqtt_count} |\n\n")
  builder.write_string("## Packet length histogram\n\n")
  builder.write_string("| Range | Packets |\n| --- | ---: |\n")
  builder.write_string("| 0-64 | \{hist.bucket_0_64} |\n")
  builder.write_string("| 65-128 | \{hist.bucket_65_128} |\n")
  builder.write_string("| 129-512 | \{hist.bucket_129_512} |\n")
  builder.write_string("| 513-1024 | \{hist.bucket_513_1024} |\n")
  builder.write_string("| 1025-1500 | \{hist.bucket_1025_1500} |\n")
  builder.write_string("| jumbo | \{hist.bucket_jumbo} |\n\n")
  builder.write_string("## Anomalies\n\n")
  if anomalies.length() == 0 {
    builder.write_string("No anomalies detected.\n")
  } else {
    builder.write_string(
      "| Packet | Severity | Kind | Description |\n| ---: | --- | --- | --- |\n",
    )
    for anomaly in anomalies {
      builder.write_string(
        "| \{anomaly.packet_idx} | \{markdown_anomaly_severity(anomaly.severity)} | \{markdown_escape(anomaly.kind)} | \{markdown_escape(anomaly.description)} |\n",
      )
    }
  }
  builder.to_string()
}
