// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: analyzer/packet_filter.mbt

///|
pub(all) enum FilterOp {
  OpEquals
  OpNotEquals
  OpGreaterThan
  OpLessThan
  OpContains
} derive(Eq, Debug)

///|
pub(all) struct FilterRule {
  field_name : String
  op : FilterOp
  value : String
} derive(Eq, Debug)

///|
pub struct ComplexPacketFilter {
  rules : Array[FilterRule]
  match_all : Bool
}

///|
pub fn ComplexPacketFilter::new(
  match_all? : Bool = true,
) -> ComplexPacketFilter {
  { rules: Array::new(), match_all }
}

///|
pub fn ComplexPacketFilter::add_rule(
  self : ComplexPacketFilter,
  field_name : String,
  op : FilterOp,
  value : String,
) -> Unit {
  self.rules.push({ field_name, op, value })
}

///|
pub fn ComplexPacketFilter::eval_rule(
  rule : FilterRule,
  field_value : String,
) -> Bool {
  match rule.op {
    OpEquals => field_value == rule.value
    OpNotEquals => field_value != rule.value
    OpContains => field_value.has_prefix(rule.value)
    _ => field_value == rule.value
  }
}

///|
pub fn ComplexPacketFilter::matches_protocol(
  self : ComplexPacketFilter,
  proto_name : String,
  packet_len : Int,
) -> Bool {
  if self.rules.length() == 0 {
    return true
  }
  let mut matched_count = 0
  for rule in self.rules {
    let mut ok = false
    if rule.field_name == "protocol" {
      ok = ComplexPacketFilter::eval_rule(rule, proto_name)
    } else if rule.field_name == "length" {
      let len_val = packet_len.to_string()
      ok = ComplexPacketFilter::eval_rule(rule, len_val)
    }
    if ok {
      matched_count = matched_count + 1
    }
  }

  if self.match_all {
    matched_count == self.rules.length()
  } else {
    matched_count > 0
  }
}
