// Unit tests for src/cli module

///|
test "cli args parsing" {
  let args = ["--json", "--proto", "tcp", "capture.pcap"]
  let opts = parse_args(args)

  inspect(opts.output_format, content="json")
  inspect(opts.filter_proto, content="tcp")
  inspect(opts.file_path, content="capture.pcap")
}

///|
test "cli runner execution" {
  let writer = @pcap.PcapWriter::new()
  writer.write_packet(
    Bytes::from_array([
      b'\x00', b'\x11', b'\x22', b'\x33', b'\x44', b'\x55', b'\x66', b'\x77', b'\x88',
      b'\x99', b'\xAA', b'\xBB', b'\x08', b'\x06',
    ]),
  )
  let pcap_bytes = writer.to_bytes()

  let opts = default_options()
  let summary = run_analysis(pcap_bytes, opts)
  assert_true(summary.length() > 0)
}
