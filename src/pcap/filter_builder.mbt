// Fluent filter configuration and diagnostics for packet processing pipelines.

///|
pub(all) struct PacketFilterSnapshot {
  min_length : Int
  max_length : Int
  target_ip : String
  target_port : UInt
  protocol : String
} derive(Eq, Debug)

///|
/// Return whether the configured range and port are meaningful.
pub fn PacketFilter::is_valid(self : PacketFilter) -> Bool {
  self.min_length >= 0 &&
  self.max_length >= self.min_length &&
  self.target_port <= 65535U
}

///|
/// Clamp a filter to safe packet lengths and valid ports.
pub fn PacketFilter::normalize(self : PacketFilter) -> Unit {
  if self.min_length < 0 {
    self.min_length = 0
  }
  if self.max_length < self.min_length {
    self.max_length = self.min_length
  }
  if self.target_port > 65535U {
    self.target_port = 0U
  }
}

///|
/// Return an immutable copy of the filter configuration.
pub fn PacketFilter::snapshot(self : PacketFilter) -> PacketFilterSnapshot {
  {
    min_length: if self.min_length < 0 {
      0
    } else {
      self.min_length
    },
    max_length: if self.max_length < self.min_length {
      self.min_length
    } else {
      self.max_length
    },
    target_ip: self.target_ip,
    target_port: if self.target_port > 65535U {
      0U
    } else {
      self.target_port
    },
    protocol: self.protocol_name,
  }
}

///|
/// Describe a filter in a stable form for CLI logging.
pub fn PacketFilter::describe(self : PacketFilter) -> String {
  let snapshot = self.snapshot()
  let protocol = if snapshot.protocol == "" { "any" } else { snapshot.protocol }
  let port = if snapshot.target_port == 0U {
    "any"
  } else {
    "\{snapshot.target_port}"
  }
  let ip = if snapshot.target_ip == "" { "any" } else { snapshot.target_ip }
  "length=\{snapshot.min_length}..\{snapshot.max_length} protocol=\{protocol} port=\{port} ip=\{ip}"
}

///|
/// Return whether a packet's captured length meets the configured range.
pub fn PacketFilter::matches_length(self : PacketFilter, length : Int) -> Bool {
  length >= self.min_length && length <= self.max_length
}

///|
/// Return whether a protocol label matches exactly; empty means any protocol.
pub fn PacketFilter::matches_protocol(
  self : PacketFilter,
  protocol : String,
) -> Bool {
  self.protocol_name == "" || self.protocol_name == protocol
}

///|
/// Return whether the target port accepts a concrete port.
pub fn PacketFilter::matches_port(self : PacketFilter, port : UInt) -> Bool {
  self.target_port == 0U || self.target_port == port
}

///|
/// Return whether the filter has no protocol/IP/port restrictions.
pub fn PacketFilter::is_length_only(self : PacketFilter) -> Bool {
  self.target_ip == "" && self.target_port == 0U && self.protocol_name == ""
}
