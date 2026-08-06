// Unit tests for src/wasm module

///|
test "wasm pcap json API" {
  let writer = @pcap.PcapWriter::new()
  writer.write_packet(Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04']))
  let pcap_bytes = writer.to_bytes()

  let json_res = wasm_analyze_pcap_json(pcap_bytes)
  assert_true(json_res.length() > 0)
}

///|
test "wasm pcap summary API" {
  let writer = @pcap.PcapWriter::new()
  writer.write_packet(Bytes::from_array([b'\xAA', b'\xBB']))
  let pcap_bytes = writer.to_bytes()

  let summary_res = wasm_analyze_pcap_summary(pcap_bytes)
  assert_true(summary_res.length() > 0)
}
