// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: analyzer/rtt.mbt

///|
pub(all) struct RttMeasurement {
  key : @reassembly.SessionKey
  syn_ts : Double
  syn_ack_ts : Double
  rtt_ms : Double
} derive(Eq, Debug)

///|
pub struct RttTracker {
  measurements : Array[RttMeasurement]
}

///|
pub fn RttTracker::new() -> RttTracker {
  { measurements: Array::new() }
}

///|
pub fn RttTracker::record_handshake(
  self : RttTracker,
  key : @reassembly.SessionKey,
  syn_ts : Double,
  syn_ack_ts : Double,
) -> Unit {
  let delta = syn_ack_ts - syn_ts
  let rtt_ms = if delta > 0.0 { delta * 1000.0 } else { 0.0 }
  self.measurements.push({ key, syn_ts, syn_ack_ts, rtt_ms })
}

///|
pub fn RttTracker::get_avg_rtt(self : RttTracker) -> Double {
  if self.measurements.length() == 0 {
    0.0
  } else {
    let mut sum = 0.0
    for m in self.measurements {
      sum = sum + m.rtt_ms
    }
    sum / self.measurements.length().to_double()
  }
}

///|
pub fn RttTracker::get_measurements(self : RttTracker) -> Array[RttMeasurement] {
  self.measurements
}
