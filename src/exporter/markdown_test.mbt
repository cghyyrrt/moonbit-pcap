///|
test "markdown exporter contains stable report sections" {
  let stats = @analyzer.TrafficStats::new()
  stats.record_packet(64, "TCP")
  let output = export_markdown_report(stats, Array::new())
  assert_true(output.contains("# Network Packet Analysis Report"))
  assert_true(output.contains("| TCP | 1 |"))
  assert_true(output.contains("No anomalies detected"))
}

///|
test "markdown table escaping protects pipe and newline characters" {
  inspect(markdown_escape("a|b\nc"), content="a\\|b c")
}
