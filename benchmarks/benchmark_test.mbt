///|
fn benchmark_packet() -> Bytes {
  Bytes::from_array([
    b'\x00', b'\x01', b'\x02', b'\x03', b'\x04', b'\x05', b'\x06', b'\x07', b'\x08',
    b'\x09', b'\x0A', b'\x0B', b'\x08', b'\x00', b'\x45', b'\x00', b'\x00', b'\x1C',
    b'\x00', b'\x01', b'\x00', b'\x00', b'\x40', b'\x11', b'\x00', b'\x00', b'\x0A',
    b'\x00', b'\x00', b'\x01', b'\x0A', b'\x00', b'\x00', b'\x02', b'\x12', b'\x34',
    b'\x00', b'\x35', b'\x00', b'\x08', b'\x00', b'\x00',
  ])
}

///|
test "bench ethernet ipv4 udp parser n=10" (it : @bench.T) {
  let packet = benchmark_packet()
  it.bench(
    () => {
      let parsed = @layers.parse_ethernet(packet)
      it.keep(parsed)
    },
    name="ethernet_ipv4_udp_parse",
    count=10,
  )
}
