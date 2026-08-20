// Structural validation reports for ingestion pipelines.

///|
pub(all) enum PcapValidationIssue {
  TruncatedGlobalHeader
  InvalidMagic
  TruncatedPacketHeader
  TruncatedPacketPayload
  ZeroCaptureLength
  SnaplenExceeded
} derive(Eq, Debug)

///|
pub(all) struct PcapValidationReport {
  valid : Bool
  packet_count : Int
  captured_bytes : Int64
  issues : Array[PcapValidationIssue]
} derive(Eq, Debug)

///|
/// Validate all structural lengths in a classic PCAP byte stream.
pub fn validate_pcap(data : Bytes) -> PcapValidationReport {
  let issues : Array[PcapValidationIssue] = []
  if data.length() < 24 {
    issues.push(TruncatedGlobalHeader)
    return { valid: false, packet_count: 0, captured_bytes: 0L, issues }
  }
  let reader = @binary.BinaryReader::new(data)
  let header = parse_magic(reader)
  if header is None {
    issues.push(InvalidMagic)
    return { valid: false, packet_count: 0, captured_bytes: 0L, issues }
  }
  let global = header.unwrap()
  let mut packet_count = 0
  let mut captured_bytes = 0L
  while reader.remaining() > 0 {
    if reader.remaining() < 16 {
      issues.push(TruncatedPacketHeader)
      break
    }
    let packet_header = parse_packet_header(reader, global.is_nanosecond)
    if packet_header is None {
      issues.push(TruncatedPacketHeader)
      break
    }
    let packet = packet_header.unwrap()
    let incl_len = packet.incl_len.reinterpret_as_int()
    if incl_len == 0 {
      issues.push(ZeroCaptureLength)
    }
    if packet.incl_len > global.snaplen {
      issues.push(SnaplenExceeded)
    }
    if !reader.has_bytes(incl_len) {
      issues.push(TruncatedPacketPayload)
      break
    }
    let _ = reader.read_bytes(incl_len)
    packet_count = packet_count + 1
    captured_bytes = captured_bytes + incl_len.to_int64()
  }
  { valid: issues.length() == 0, packet_count, captured_bytes, issues }
}

///|
/// Return a compact error summary suitable for a CLI.
pub fn PcapValidationReport::summary(self : PcapValidationReport) -> String {
  if self.valid {
    "valid PCAP"
  } else {
    "invalid PCAP: \{self.issues.length()} issue(s)"
  }
}

///|
/// Return whether validation found no structural issues.
pub fn PcapValidationReport::is_valid(self : PcapValidationReport) -> Bool {
  self.valid
}
