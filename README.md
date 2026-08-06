# moonbit-pcap: MoonBit Network Packet Capture & Protocol Analysis Library

`moonbit-pcap` is a pure MoonBit high-performance library for reading, parsing, reassembling, analyzing, and exporting PCAP and PCAPNG network packet capture files.

## Features
- **PCAP & PCAPNG Parsing**: Auto endianness detection, PCAP global & packet headers, PCAPNG Section (SHB), Interface (IDB), Enhanced Packet (EPB), Simple Packet (SPB), Interface Statistics (ISB), Name Resolution (NRB), and options parsing.
- **Multi-Layer Protocol Dissectors**:
  - Layer 2: Ethernet II, 802.1Q/802.1ad VLAN tags
  - Layer 2.5: ARP / RARP
  - Layer 3: IPv4 (header, options, checksum, flags), IPv6 (extension headers)
  - Layer 4: ICMPv4/v6, UDP, TCP (flags, MSS, Window Scale, SACK, Timestamps)
  - Layer 7: DNS (name pointer decompression, RR types A/AAAA/CNAME/MX/TXT/NS/PTR/SRV), CAN-over-PCAP (SocketCAN), Modbus TCP (MBAP & function codes), MQTT.
- **TCP Stream Reassembly**: Canonical 5-tuple indexing (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`), out-of-order segment buffer, sequence overlap resolution, continuous stream payload reconstruction.
- **Network Traffic Analytics**: Statistics counters, packet length distribution histogram, RTT estimation, security anomaly detection (checksum failures, SYN flood, port scanning).
- **Exporters & Interface**: JSON exporter, CSV exporter, Terminal ASCII summary table formatter, CLI runner, WASM interop interface.

## License
Apache-2.0 License.
