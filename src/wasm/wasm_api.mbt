// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: wasm/wasm_api.mbt

///|
pub fn wasm_analyze_pcap_json(data : Bytes) -> String {
  let stats = @analyzer.TrafficStats::new()
  let reader_opt = @pcap.PcapReader::new(data)
  if reader_opt is Some(reader) {
    let pkts = reader.read_all()
    for pkt in pkts {
      stats.record_packet(pkt.payload.length(), "ETH")
    }
  }
  @exporter.export_stats_json(stats)
}

///|
pub fn wasm_analyze_pcap_summary(data : Bytes) -> String {
  let stats = @analyzer.TrafficStats::new()
  let anomalies = Array::new()
  let reader_opt = @pcap.PcapReader::new(data)
  if reader_opt is Some(reader) {
    let pkts = reader.read_all()
    for pkt in pkts {
      stats.record_packet(pkt.payload.length(), "ETH")
    }
  }
  @exporter.export_terminal_summary(stats, anomalies)
}
