// Structural validation for PCAPNG streams before expensive packet decoding.

///|
pub(all) enum PcapngValidationIssue {
  TruncatedBlockHeader
  InvalidBlockLength
  TruncatedBlockBody
  InvalidTrailingLength
  UnalignedBlockLength
} derive(Eq, Debug)

///|
pub(all) struct PcapngValidationReport {
  valid : Bool
  block_count : Int
  packet_count : Int
  total_packet_bytes : Int64
  issues : Array[PcapngValidationIssue]
} derive(Eq, Debug)

///|
/// Validate block framing and count EPB packet bytes without decoding payloads.
pub fn validate_pcapng(data : Bytes) -> PcapngValidationReport {
  let reader = @binary.BinaryReader::new(data)
  let issues : Array[PcapngValidationIssue] = []
  let mut block_count = 0
  let mut packet_count = 0
  let mut total_packet_bytes = 0L
  while reader.remaining() > 0 {
    if reader.remaining() < 12 {
      issues.push(TruncatedBlockHeader)
      break
    }
    let block_type = reader.read_u32()
    let block_len = reader.read_u32().reinterpret_as_int()
    if block_len < 12 {
      issues.push(InvalidBlockLength)
      break
    }
    if block_len % 4 != 0 {
      issues.push(UnalignedBlockLength)
    }
    let body_len = block_len - 12
    if !reader.has_bytes(body_len + 4) {
      issues.push(TruncatedBlockBody)
      break
    }
    let body_start = reader.tell()
    if block_type == 0x00000006U && body_len >= 24 {
      let _ = reader.read_u32()
      let _ = reader.read_u32()
      let _ = reader.read_u32()
      let cap_len = reader.read_u32().reinterpret_as_int()
      let _ = reader.read_u32()
      if cap_len < 0 || cap_len > reader.remaining() {
        issues.push(TruncatedBlockBody)
      } else {
        packet_count = packet_count + 1
        total_packet_bytes = total_packet_bytes + cap_len.to_int64()
      }
    }
    reader.seek(body_start + body_len)
    let trailing = reader.read_u32().reinterpret_as_int()
    if trailing != block_len {
      issues.push(InvalidTrailingLength)
    }
    block_count = block_count + 1
  }
  {
    valid: issues.length() == 0,
    block_count,
    packet_count,
    total_packet_bytes,
    issues,
  }
}

///|
/// Return a compact validation summary.
pub fn PcapngValidationReport::summary(self : PcapngValidationReport) -> String {
  if self.valid {
    "valid PCAPNG"
  } else {
    "invalid PCAPNG: \{self.issues.length()} issue(s)"
  }
}
