// MoonBit Network Packet Capture & Protocol Analysis Library
// Module: cli/runner.mbt

///|
pub fn run_analysis(data : Bytes, opts : CliOptions) -> String {
  let stats = @analyzer.TrafficStats::new()
  let detector = @analyzer.AnomalyDetector::new()
  let packets = Array::new()

  // Try parsing as PCAP classic first
  let pcap_reader = @pcap.PcapReader::new(data)
  if pcap_reader is Some(reader) {
    let raw_packets = reader.read_all()
    let mut idx = 1
    for pkt in raw_packets {
      packets.push(pkt)
      let eth_opt = @layers.parse_ethernet(pkt.payload)
      if eth_opt is Some(eth) {
        stats.record_packet(pkt.payload.length(), "ETH")
        if eth.ethertype == 0x0800U {
          stats.record_packet(pkt.payload.length(), "IPv4")
          let ip_opt = @layers.parse_ipv4(eth.payload)
          if ip_opt is Some(ip) {
            if opts.anomaly_check {
              detector.check_checksum(
                ip.is_checksum_valid,
                "IPv4",
                idx,
                pkt.timestamp,
              )
            }
            if ip.protocol == b'\x06' {
              stats.record_packet(pkt.payload.length(), "TCP")
              let tcp_opt = @layers.parse_tcp(ip.payload)
              if tcp_opt is Some(tcp) {
                if opts.anomaly_check {
                  detector.record_tcp_flags(
                    tcp.flag_syn,
                    tcp.flag_ack,
                    tcp.flag_rst,
                    idx,
                    pkt.timestamp,
                  )
                }
              }
            } else if ip.protocol == b'\x11' {
              stats.record_packet(pkt.payload.length(), "UDP")
              let udp_opt = @layers.parse_udp(ip.payload)
              if udp_opt is Some(udp) {
                if udp.src_port == 53U || udp.dst_port == 53U {
                  stats.record_packet(pkt.payload.length(), "DNS")
                }
              }
            } else if ip.protocol == b'\x01' {
              stats.record_packet(pkt.payload.length(), "ICMP")
            }
          }
        } else if eth.ethertype == 0x0806U {
          stats.record_packet(pkt.payload.length(), "ARP")
        }
      }
      idx = idx + 1
    }
  } else {
    // Try PCAPNG
    let pcapng_reader = @pcapng.PcapngReader::new(data)
    let epbs = pcapng_reader.read_all_packets()
    let mut idx = 1
    for epb in epbs {
      let pkt_hdr : @pcap.PcapPacketHeader = {
        ts_sec: epb.timestamp_high,
        ts_usec: epb.timestamp_low,
        incl_len: epb.cap_len,
        orig_len: epb.orig_len,
      }
      let pkt : @pcap.PcapPacket = {
        header: pkt_hdr,
        payload: epb.packet_data,
        timestamp: epb.timestamp,
      }
      packets.push(pkt)
      stats.record_packet(epb.packet_data.length(), "ETH")
      idx = idx + 1
    }
  }

  let anomalies = detector.get_anomalies()
  match opts.output_format {
    "json" => @exporter.export_stats_json(stats)
    "csv" => @exporter.export_packets_csv(packets)
    _ => @exporter.export_terminal_summary(stats, anomalies)
  }
}
