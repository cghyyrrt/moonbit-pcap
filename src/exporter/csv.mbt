// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: exporter/csv.mbt

///|
pub fn export_packets_csv(packets : Array[@pcap.PcapPacket]) -> String {
  let buf = StringBuilder::new()
  buf.write_string(
    "No,Time_Sec,Time_Usec,Captured_Length,Original_Length,Payload_Hex_Snippet\n",
  )

  for i = 0; i < packets.length(); i = i + 1 {
    let pkt = packets[i]
    let snippet_len = if pkt.payload.length() < 16 {
      pkt.payload.length()
    } else {
      16
    }
    let snippet_bytes = if snippet_len > 0 {
      let arr : Array[Byte] = Array::make(snippet_len, b'\x00')
      for k = 0; k < snippet_len; k = k + 1 {
        arr[k] = pkt.payload[k]
      }
      Bytes::from_array(arr)
    } else {
      Bytes::from_array([])
    }
    let hex_snip = @binary.bytes_to_hex(snippet_bytes)
    buf.write_string(
      "\{i + 1},\{pkt.header.ts_sec},\{pkt.header.ts_usec},\{pkt.header.incl_len},\{pkt.header.orig_len},\{hex_snip}\n",
    )
  }
  buf.to_string()
}
