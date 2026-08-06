// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: layers/dns.mbt

///|
pub(all) struct DnsHeader {
  id : UInt
  qr : Bool
  opcode : Byte
  aa : Bool
  tc : Bool
  rd : Bool
  ra : Bool
  z : Byte
  rcode : Byte
  qdcount : UInt
  ancount : UInt
  nscount : UInt
  arcount : UInt
} derive(Eq, Debug)

///|
pub(all) struct DnsQuestion {
  qname : String
  qtype : UInt
  qclass : UInt
} derive(Eq, Debug)

///|
pub(all) struct DnsResourceRecord {
  name : String
  rtype : UInt
  rclass : UInt
  ttl : UInt
  rdlength : UInt
  rdata : Bytes
  rdata_str : String
} derive(Eq, Debug)

///|
pub(all) struct DnsPacket {
  header : DnsHeader
  questions : Array[DnsQuestion]
  answers : Array[DnsResourceRecord]
  authorities : Array[DnsResourceRecord]
  additionals : Array[DnsResourceRecord]
} derive(Eq, Debug)

///|
pub fn decode_domain_name(reader : @binary.BinaryReader) -> String {
  let labels = Array::new()
  let mut jumped = false
  let mut jump_count = 0
  let original_pos = reader.tell()

  while reader.has_bytes(1) && jump_count < 10 {
    let len = reader.read_u8().to_int()
    if len == 0 {
      break
    }
    if (len & 0xC0) == 0xC0 {
      // Pointer compression
      if !reader.has_bytes(1) {
        break
      }
      let b2 = reader.read_u8().to_int()
      let offset = ((len & 0x3F) << 8) | b2
      if !jumped {
        jumped = true
      }
      jump_count = jump_count + 1
      reader.seek(offset)
    } else {
      if !reader.has_bytes(len) {
        break
      }
      let label_bytes = reader.read_bytes(len)
      let buf = StringBuilder::new()
      for i = 0; i < len; i = i + 1 {
        let b = label_bytes[i].to_int()
        if b >= 32 && b <= 126 {
          buf.write_char(b.unsafe_to_char())
        }
      }
      labels.push(buf.to_string())
    }
  }

  if jumped {
    reader.seek(original_pos + 2)
  }

  let res = StringBuilder::new()
  for i = 0; i < labels.length(); i = i + 1 {
    if i > 0 {
      res.write_string(".")
    }
    res.write_string(labels[i])
  }
  res.to_string()
}

///|
pub fn parse_dns(data : Bytes) -> DnsPacket? {
  let reader = @binary.BinaryReader::new(data, endian=@binary.BigEndian)
  if !reader.has_bytes(12) {
    return None
  }
  let id = reader.read_u16()
  let flags = reader.read_u16()

  let qr = ((flags >> 15) & 0x01U) != 0U
  let opcode = ((flags >> 11) & 0x0FU).reinterpret_as_int().to_byte()
  let aa = ((flags >> 10) & 0x01U) != 0U
  let tc = ((flags >> 9) & 0x01U) != 0U
  let rd = ((flags >> 8) & 0x01U) != 0U
  let ra = ((flags >> 7) & 0x01U) != 0U
  let z = ((flags >> 4) & 0x07U).reinterpret_as_int().to_byte()
  let rcode = (flags & 0x0FU).reinterpret_as_int().to_byte()

  let qdcount = reader.read_u16()
  let ancount = reader.read_u16()
  let nscount = reader.read_u16()
  let arcount = reader.read_u16()

  let header = {
    id,
    qr,
    opcode,
    aa,
    tc,
    rd,
    ra,
    z,
    rcode,
    qdcount,
    ancount,
    nscount,
    arcount,
  }

  let questions = Array::new()
  let qd_int = qdcount.reinterpret_as_int()
  for i = 0; i < qd_int; i = i + 1 {
    let qname = decode_domain_name(reader)
    if !reader.has_bytes(4) {
      break
    }
    let qtype = reader.read_u16()
    let qclass = reader.read_u16()
    questions.push({ qname, qtype, qclass })
  }

  let parse_rr_list = fn(count : UInt) -> Array[DnsResourceRecord] {
    let list = Array::new()
    let cnt_int = count.reinterpret_as_int()
    for i = 0; i < cnt_int; i = i + 1 {
      let name = decode_domain_name(reader)
      if !reader.has_bytes(10) {
        break
      }
      let rtype = reader.read_u16()
      let rclass = reader.read_u16()
      let ttl = reader.read_u32()
      let rdlength = reader.read_u16()
      let rd_len_int = rdlength.reinterpret_as_int()
      let rdata = if reader.has_bytes(rd_len_int) {
        reader.read_bytes(rd_len_int)
      } else {
        Bytes::from_array([])
      }
      let rdata_str = match rtype {
        1U => @binary.ip4_to_string(rdata) // A record
        28U => @binary.ip6_to_string(rdata) // AAAA record
        _ => @binary.bytes_to_hex(rdata)
      }
      list.push({ name, rtype, rclass, ttl, rdlength, rdata, rdata_str })
    }
    list
  }

  let answers = parse_rr_list(ancount)
  let authorities = parse_rr_list(nscount)
  let additionals = parse_rr_list(arcount)

  Some({ header, questions, answers, authorities, additionals })
}
