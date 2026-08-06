// Unit tests for src/binary module

///|
test "binary reader endianness" {
  let arr : Array[Byte] = [b'\x01', b'\x02', b'\x03', b'\x04']
  let bytes = Bytes::from_array(arr)

  let r_le = BinaryReader::new(bytes, endian=LittleEndian)
  inspect(r_le.read_u16(), content="513") // 0x0201 = 513
  inspect(r_le.read_u16(), content="1027") // 0x0403 = 1027

  let r_be = BinaryReader::new(bytes, endian=BigEndian)
  inspect(r_be.read_u16(), content="258") // 0x0102 = 258
  inspect(r_be.read_u16(), content="772") // 0x0304 = 772
}

///|
test "binary writer & reader roundtrip" {
  let writer = BinaryWriter::new(endian=BigEndian)
  writer.write_u8(b'\x42')
  writer.write_u16(0x1234U)
  writer.write_u32(0xDEADBEEFU)
  let bytes = writer.to_bytes()

  let reader = BinaryReader::new(bytes, endian=BigEndian)
  inspect(reader.read_u8(), content="b'\\x42'")
  inspect(reader.read_u16(), content="4660")
  inspect(reader.read_u32(), content="3735928559")
}

///|
test "hex & ip formatters" {
  let ip_bytes = Bytes::from_array([b'\xC0', b'\xA8', b'\x01', b'\x01'])
  inspect(ip4_to_string(ip_bytes), content="192.168.1.1")

  let mac_bytes = Bytes::from_array([
    b'\x00', b'\x11', b'\x22', b'\x33', b'\x44', b'\x55',
  ])
  inspect(mac_to_string(mac_bytes), content="00:11:22:33:44:55")
}

///|
test "checksum internet RFC 1071" {
  let pkt = Bytes::from_array([
    b'\x45', b'\x00', b'\x00', b'\x3c', b'\x1c', b'\x46', b'\x40', b'\x00', b'\x40',
    b'\x06', b'\x00', b'\x00', b'\xac', b'\x10', b'\x0a', b'\x63', b'\xac', b'\x10',
    b'\x0a', b'\x0c',
  ])
  let csum = internet_checksum(pkt, 0, pkt.length())
  assert_true(csum > 0U)
}
