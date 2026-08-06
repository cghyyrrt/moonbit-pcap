// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: reassembly/tuple.mbt

///|
pub(all) struct SessionKey {
  src_ip : String
  src_port : UInt
  dst_ip : String
  dst_port : UInt
  protocol : Byte
} derive(Eq, Debug)

///|
pub fn SessionKey::new(
  src_ip : String,
  src_port : UInt,
  dst_ip : String,
  dst_port : UInt,
  protocol? : Byte = b'\x06',
) -> SessionKey {
  { src_ip, src_port, dst_ip, dst_port, protocol }
}

///|
pub fn SessionKey::canonical(self : SessionKey) -> SessionKey {
  let ep1 = "\{self.src_ip}:\{self.src_port}"
  let ep2 = "\{self.dst_ip}:\{self.dst_port}"
  if ep1 < ep2 {
    self
  } else {
    {
      src_ip: self.dst_ip,
      src_port: self.dst_port,
      dst_ip: self.src_ip,
      dst_port: self.src_port,
      protocol: self.protocol,
    }
  }
}

///|
pub fn SessionKey::to_string(self : SessionKey) -> String {
  let proto_str = match self.protocol {
    b'\x06' => "TCP"
    b'\x11' => "UDP"
    b'\x01' => "ICMP"
    _ => "PROTO_\{self.protocol.to_int()}"
  }
  "[\{proto_str}] \{self.src_ip}:\{self.src_port} <-> \{self.dst_ip}:\{self.dst_port}"
}
