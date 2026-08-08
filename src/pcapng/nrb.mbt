// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: pcapng/nrb.mbt

///|
pub(all) struct NameRecord {
  record_type : UInt // 1 = IPv4, 2 = IPv6
  ip_address : Bytes
  hostnames : Array[String]
} derive(Eq, Debug)

///|
pub struct NameResolver {
  records : Array[NameRecord]
}

///|
pub fn NameResolver::new() -> NameResolver {
  { records: Array::new() }
}

///|
pub fn NameResolver::add_record(self : NameResolver, rec : NameRecord) -> Unit {
  self.records.push(rec)
}

///|
pub fn NameResolver::resolve_ip4(
  self : NameResolver,
  ip_str : String,
) -> String? {
  for rec in self.records {
    if rec.record_type == 1U {
      let rec_ip = @binary.ip4_to_string(rec.ip_address)
      if rec_ip == ip_str && rec.hostnames.length() > 0 {
        return Some(rec.hostnames[0])
      }
    }
  }
  None
}

///|
pub fn NameResolver::get_all_records(self : NameResolver) -> Array[NameRecord] {
  self.records
}
