// Unit tests for src/pcap module

///|
test "pcap writer and reader roundtrip" {
  let writer = PcapWriter::new(endian=@binary.LittleEndian, network=1U)
  let pkt1_payload = Bytes::from_array([b'\x01', b'\x02', b'\x03', b'\x04'])
  let pkt2_payload = Bytes::from_array([
    b'\xAA', b'\xBB', b'\xCC', b'\xDD', b'\xEE',
  ])

  writer.write_packet(pkt1_payload, ts_sec=1600000000U, ts_usec=500000U)
  writer.write_packet(pkt2_payload, ts_sec=1600000001U, ts_usec=123456U)

  let pcap_bytes = writer.to_bytes()

  let reader_opt = PcapReader::new(pcap_bytes)
  assert_true(reader_opt is Some(_))

  let reader = reader_opt.unwrap()
  let header = reader.get_global_header()
  inspect(header.network, content="1")
  inspect(header.version_major, content="2")

  let pkts = reader.read_all()
  inspect(pkts.length(), content="2")
  inspect(pkts[0].header.ts_sec, content="1600000000")
  inspect(pkts[0].payload.length(), content="4")
  inspect(pkts[1].header.ts_sec, content="1600000001")
  inspect(pkts[1].payload.length(), content="5")
}
