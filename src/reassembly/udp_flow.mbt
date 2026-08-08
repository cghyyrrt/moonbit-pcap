// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: reassembly/udp_flow.mbt

///|
pub(all) struct UdpFlow {
  key : SessionKey
  mut packet_count : Int
  mut total_bytes : Int64
  first_seen : Double
  mut last_seen : Double
} derive(Eq, Debug)

///|
pub struct UdpFlowTracker {
  flows : Array[UdpFlow]
}

///|
pub fn UdpFlowTracker::new() -> UdpFlowTracker {
  { flows: Array::new() }
}

///|
pub fn UdpFlowTracker::record_packet(
  self : UdpFlowTracker,
  key : SessionKey,
  pkt_len : Int,
  ts : Double,
) -> Unit {
  let canon_key = key.canonical()
  let mut found = false

  for flow in self.flows {
    if flow.key == canon_key {
      flow.packet_count = flow.packet_count + 1
      flow.total_bytes = flow.total_bytes + pkt_len.to_int64()
      flow.last_seen = ts
      found = true
      break
    }
  }

  if !found {
    self.flows.push({
      key: canon_key,
      packet_count: 1,
      total_bytes: pkt_len.to_int64(),
      first_seen: ts,
      last_seen: ts,
    })
  }
}

///|
pub fn UdpFlowTracker::get_flows(self : UdpFlowTracker) -> Array[UdpFlow] {
  self.flows
}
