// MoonBit Network Packet Capture & Protocol Analysis Library
// Executable main entrypoint

///|
fn main {
  println("==========================================================")
  println("  moonbit-pcap v0.1.1 - Network Packet Capture & Analyzer ")
  println("  MoonBit network packet analysis toolkit                  ")
  println("==========================================================")
  println("Usage: moon run cmd/main -- <pcap_file> [--json|--csv]")

  // Synthetic demo capture verification
  let writer = @pcap.PcapWriter::new()
  writer.write_packet(
    Bytes::from_array([
      b'\x00', b'\x11', b'\x22', b'\x33', b'\x44', b'\x55', b'\x66', b'\x77', b'\x88',
      b'\x99', b'\xAA', b'\xBB', b'\x08', b'\x00', b'\x45', b'\x00', b'\x00', b'\x28',
      b'\x00', b'\x01', b'\x00', b'\x00', b'\x40', b'\x06', b'\x7C', b'\xCD', b'\xC0',
      b'\xA8', b'\x01', b'\x01', b'\xC0', b'\xA8', b'\x01', b'\x02', b'\x00', b'\x50',
      b'\x01', b'\xBB', b'\x00', b'\x00', b'\x00', b'\x01', b'\x00', b'\x00', b'\x00',
      b'\x00', b'\x50', b'\x02', b'\x20', b'\x00', b'\x91', b'\x7C', b'\x00', b'\x00',
    ]),
    ts_sec=1700000000U,
    ts_usec=123456U,
  )
  let pcap_bytes = writer.to_bytes()
  let opts = @cli.default_options()
  let summary = @cli.run_analysis(pcap_bytes, opts)
  println(summary)
}
