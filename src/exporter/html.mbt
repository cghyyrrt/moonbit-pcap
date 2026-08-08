// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: exporter/html.mbt

///|
pub fn export_html_report(
  stats : @analyzer.TrafficStats,
  anomalies : Array[@analyzer.NetworkAnomaly],
) -> String {
  let buf = StringBuilder::new()
  let dist = stats.get_protocol_distribution()
  let hist = stats.get_length_histogram()

  buf.write_string("<!DOCTYPE html>\n<html>\n<head>\n")
  buf.write_string("  <meta charset=\"UTF-8\">\n")
  buf.write_string("  <title>MoonBit PCAP Analysis Report</title>\n")
  buf.write_string("  <style>\n")
  buf.write_string(
    "    body { font-family: system-ui, sans-serif; background: #0f172a; color: #f8fafc; margin: 2rem; }\n",
  )
  buf.write_string("    h1, h2 { color: #38bdf8; }\n")
  buf.write_string(
    "    .card { background: #1e293b; padding: 1.5rem; border-radius: 8px; margin-bottom: 1.5rem; }\n",
  )
  buf.write_string(
    "    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }\n",
  )
  buf.write_string(
    "    th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #334155; }\n",
  )
  buf.write_string("    th { background: #0284c7; color: white; }\n")
  buf.write_string(
    "    .badge-high { background: #ef4444; color: white; padding: 0.2rem 0.5rem; border-radius: 4px; }\n",
  )
  buf.write_string("  </style>\n</head>\n<body>\n")
  buf.write_string("  <h1>MoonBit Network Packet Analysis Report</h1>\n")

  buf.write_string("  <div class=\"card\">\n")
  buf.write_string("    <h2>Traffic Overview</h2>\n")
  buf.write_string(
    "    <p>Total Packets: <strong>\{stats.get_total_packets()}</strong></p>\n",
  )
  buf.write_string(
    "    <p>Total Bytes: <strong>\{stats.get_total_bytes()} B</strong></p>\n",
  )
  buf.write_string(
    "    <p>Average Packet Length: <strong>\{stats.get_avg_length()} B</strong></p>\n",
  )
  buf.write_string("  </div>\n")

  buf.write_string("  <div class=\"card\">\n")
  buf.write_string("    <h2>Protocol Distribution</h2>\n")
  buf.write_string("    <table>\n<tr><th>Protocol</th><th>Count</th></tr>\n")
  buf.write_string(
    "      <tr><td>Ethernet</td><td>\{dist.eth_count}</td></tr>\n",
  )
  buf.write_string("      <tr><td>IPv4</td><td>\{dist.ip4_count}</td></tr>\n")
  buf.write_string("      <tr><td>IPv6</td><td>\{dist.ip6_count}</td></tr>\n")
  buf.write_string("      <tr><td>TCP</td><td>\{dist.tcp_count}</td></tr>\n")
  buf.write_string("      <tr><td>UDP</td><td>\{dist.udp_count}</td></tr>\n")
  buf.write_string("      <tr><td>DNS</td><td>\{dist.dns_count}</td></tr>\n")
  buf.write_string(
    "      <tr><td>Modbus TCP</td><td>\{dist.modbus_count}</td></tr>\n",
  )
  buf.write_string("    </table>\n  </div>\n")

  buf.write_string("  <div class=\"card\">\n")
  buf.write_string("    <h2>Packet Length Distribution</h2>\n")
  buf.write_string(
    "    <table>\n<tr><th>Length Bin</th><th>Packets</th></tr>\n",
  )
  buf.write_string(
    "      <tr><td>0 - 64 B</td><td>\{hist.bucket_0_64}</td></tr>\n",
  )
  buf.write_string(
    "      <tr><td>65 - 128 B</td><td>\{hist.bucket_65_128}</td></tr>\n",
  )
  buf.write_string(
    "      <tr><td>129 - 512 B</td><td>\{hist.bucket_129_512}</td></tr>\n",
  )
  buf.write_string(
    "      <tr><td>513 - 1024 B</td><td>\{hist.bucket_513_1024}</td></tr>\n",
  )
  buf.write_string(
    "      <tr><td>1025 - 1500 B</td><td>\{hist.bucket_1025_1500}</td></tr>\n",
  )
  buf.write_string("    </table>\n  </div>\n")

  buf.write_string("  <div class=\"card\">\n")
  buf.write_string("    <h2>Security Anomalies</h2>\n")
  if anomalies.length() == 0 {
    buf.write_string("    <p>No anomalies detected.</p>\n")
  } else {
    buf.write_string(
      "    <table>\n<tr><th>Packet #</th><th>Kind</th><th>Description</th></tr>\n",
    )
    for a in anomalies {
      buf.write_string(
        "      <tr><td>#\{a.packet_idx}</td><td><span class=\"badge-high\">\{a.kind}</span></td><td>\{a.description}</td></tr>\n",
      )
    }
    buf.write_string("    </table>\n")
  }
  buf.write_string("  </div>\n</body>\n</html>")

  buf.to_string()
}
