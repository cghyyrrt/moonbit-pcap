// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: analyzer/anomaly.mbt

///|
pub(all) enum AnomalySeverity {
  Low
  Medium
  High
  Critical
} derive(Eq, Debug)

///|
pub(all) struct NetworkAnomaly {
  kind : String
  severity : AnomalySeverity
  description : String
  packet_idx : Int
  timestamp : Double
} derive(Eq, Debug)

///|
pub struct AnomalyDetector {
  anomalies : Array[NetworkAnomaly]
  mut syn_count : Int
  mut ack_count : Int
}

///|
pub fn AnomalyDetector::new() -> AnomalyDetector {
  { anomalies: Array::new(), syn_count: 0, ack_count: 0 }
}

///|
pub fn AnomalyDetector::report_anomaly(
  self : AnomalyDetector,
  kind : String,
  severity : AnomalySeverity,
  description : String,
  packet_idx : Int,
  timestamp : Double,
) -> Unit {
  self.anomalies.push({ kind, severity, description, packet_idx, timestamp })
}

///|
pub fn AnomalyDetector::check_checksum(
  self : AnomalyDetector,
  is_valid : Bool,
  proto_name : String,
  pkt_idx : Int,
  ts : Double,
) -> Unit {
  if !is_valid {
    self.report_anomaly(
      "ChecksumMismatch",
      AnomalySeverity::Medium,
      "Invalid \{proto_name} checksum detected in packet #\{pkt_idx}",
      pkt_idx,
      ts,
    )
  }
}

///|
pub fn AnomalyDetector::record_tcp_flags(
  self : AnomalyDetector,
  syn : Bool,
  ack : Bool,
  rst : Bool,
  pkt_idx : Int,
  ts : Double,
) -> Unit {
  let _ = rst
  if syn && !ack {
    self.syn_count = self.syn_count + 1
  }
  if ack {
    self.ack_count = self.ack_count + 1
  }

  if self.syn_count > 50 && self.ack_count == 0 {
    self.report_anomaly(
      "SynFloodSuspicion",
      AnomalySeverity::High,
      "High volume of unanswered SYN requests detected (\{self.syn_count} SYNs)",
      pkt_idx,
      ts,
    )
  }
}

///|
pub fn AnomalyDetector::get_anomalies(
  self : AnomalyDetector,
) -> Array[NetworkAnomaly] {
  self.anomalies
}
