// Query and normalization helpers shared by CLI and report exporters.

///|
pub(all) struct StatsSnapshot {
  packets : Int
  bytes : Int64
  minimum_size : Int
  maximum_size : Int
  average_size : Double
} derive(Eq, Debug)

///|
pub(all) struct AnomalyCounts {
  low_or_medium : Int
  high_or_critical : Int
  critical : Int
} derive(Eq, Debug)

///|
/// Create an immutable view of the current traffic totals.
pub fn snapshot_stats(stats : TrafficStats) -> StatsSnapshot {
  {
    packets: stats.get_total_packets(),
    bytes: stats.get_total_bytes(),
    minimum_size: stats.get_min_len(),
    maximum_size: stats.get_max_len(),
    average_size: stats.get_avg_length(),
  }
}

///|
/// Convert bytes per second to MiB/s; invalid durations return zero.
pub fn throughput_mib_per_second(bytes : Int64, seconds : Double) -> Double {
  if bytes <= 0L || seconds <= 0.0 {
    0.0
  } else {
    bytes.to_double() / seconds / 1048576.0
  }
}

///|
/// Group anomaly severities for dashboards.
pub fn summarize_anomalies(anomalies : Array[NetworkAnomaly]) -> AnomalyCounts {
  let mut low_or_medium = 0
  let mut high_or_critical = 0
  let mut critical = 0
  for anomaly in anomalies {
    match anomaly.severity {
      Low | Medium => low_or_medium = low_or_medium + 1
      High => high_or_critical = high_or_critical + 1
      Critical => {
        high_or_critical = high_or_critical + 1
        critical = critical + 1
      }
    }
  }
  { low_or_medium, high_or_critical, critical }
}

///|
/// Return true when at least one critical anomaly is present.
pub fn has_critical_anomaly(anomalies : Array[NetworkAnomaly]) -> Bool {
  for anomaly in anomalies {
    if anomaly.severity is Critical {
      return true
    }
  }
  false
}

///|
/// Return true for anomalies that should appear in an incident banner.
pub fn is_high_risk(severity : AnomalySeverity) -> Bool {
  severity is High || severity is Critical
}

///|
/// Return a normalized duration, preventing negative capture spans.
pub fn normalize_duration(start : Double, finish : Double) -> Double {
  if finish <= start {
    0.0
  } else {
    finish - start
  }
}

///|
/// Return packets per second for a non-empty interval.
pub fn packets_per_second(packets : Int, seconds : Double) -> Double {
  if packets <= 0 || seconds <= 0.0 {
    0.0
  } else {
    packets.to_double() / seconds
  }
}

///|
/// Return bytes per second for a non-empty interval.
pub fn bytes_per_second(bytes : Int64, seconds : Double) -> Double {
  if bytes <= 0L || seconds <= 0.0 {
    0.0
  } else {
    bytes.to_double() / seconds
  }
}

///|
/// Format a byte count using binary units without losing the exact count for bytes.
pub fn format_bytes(bytes : Int64) -> String {
  if bytes < 0L {
    "0 B"
  } else if bytes < 1024L {
    "\{bytes} B"
  } else if bytes < 1048576L {
    "\{bytes.to_double() / 1024.0} KiB"
  } else {
    "\{bytes.to_double() / 1048576.0} MiB"
  }
}
