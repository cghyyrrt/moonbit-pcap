// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: analyzer/session_analyzer.mbt

///|
pub(all) struct SessionSummary {
  key : @reassembly.SessionKey
  mut packet_count : Int
  mut total_bytes : Int64
  first_seen_ts : Double
  mut last_seen_ts : Double
  mut duration_sec : Double
} derive(Eq, Debug)

///|
pub struct SessionProfiler {
  sessions : Array[SessionSummary]
}

///|
pub fn SessionProfiler::new() -> SessionProfiler {
  { sessions: Array::new() }
}

///|
pub fn SessionProfiler::record_packet(
  self : SessionProfiler,
  key : @reassembly.SessionKey,
  bytes_len : Int,
  ts : Double,
) -> Unit {
  let canon_key = key.canonical()
  let mut found = false

  for s in self.sessions {
    if s.key == canon_key {
      s.packet_count = s.packet_count + 1
      s.total_bytes = s.total_bytes + bytes_len.to_int64()
      s.last_seen_ts = ts
      s.duration_sec = s.last_seen_ts - s.first_seen_ts
      found = true
      break
    }
  }

  if !found {
    self.sessions.push({
      key: canon_key,
      packet_count: 1,
      total_bytes: bytes_len.to_int64(),
      first_seen_ts: ts,
      last_seen_ts: ts,
      duration_sec: 0.0,
    })
  }
}

///|
pub fn SessionProfiler::get_active_sessions(
  self : SessionProfiler,
) -> Array[SessionSummary] {
  self.sessions
}
