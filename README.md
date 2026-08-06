# `moonbit-pcap` — MoonBit Network Packet Capture & Protocol Analysis Library

[![MoonBit Version](https://img.shields.io/badge/MoonBit-0.10.4-blue.svg)](https://www.moonbitlang.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)
[![CI Status](https://img.shields.io/badge/CI-Passing-brightgreen.svg)](#)

`moonbit-pcap` is a pure MoonBit high-performance library for reading, parsing, reassembling, analyzing, and exporting PCAP and PCAPNG network packet capture files. Built from the ground up without external C bindings or libpcap dependencies, `moonbit-pcap` provides end-to-end support from binary endianness handling to Layer 2–Layer 7 protocol dissectors, 5-tuple TCP stream reassembly, traffic analytics, anomaly detection, CLI tools, and WASM web integration.

---

## 🌟 Key Features

- **Binary Endianness & Stream Buffer Engine**:
  - Auto endianness detection (`LittleEndian` and `BigEndian`) for header parsing.
  - Internet Checksum (RFC 1071) calculation and verification.
  - Byte array formatting, Hex dumping, MAC, IPv4, and IPv6 address formatters.
- **Full PCAP & PCAPNG File Container Parser**:
  - **PCAP Classic**: Microsecond (`0xa1b2c3d4` / `0xd4c3b2a1`) and Nanosecond (`0xa1b23c4d` / `0x4d3cb2a1`) global headers, packet headers, streaming packet iterators, and synthetic PCAP writer.
  - **PCAPNG Blocks**: Section Header Block (SHB), Interface Description Block (IDB), Enhanced Packet Block (EPB), Simple Packet Block (SPB), Interface Statistics Block (ISB), Name Resolution Block (NRB), and Option TLV parser (`if_name`, `if_tsresol`, `shb_os`, `comment`, etc.).
- **Multi-Layer Protocol Dissectors**:
  - **Layer 2 (Data Link)**: Ethernet II framing, 802.1Q / 802.1ad QinQ dual VLAN tag extraction.
  - **Layer 2.5**: ARP / RARP protocol request & reply header parser.
  - **Layer 3 (Network)**: IPv4 (header checksum validation, flags DF/MF, fragment offset, options) and IPv6 (extension header chain traversal: Hop-by-Hop, Routing, Fragment, Destination Options).
  - **Layer 4 (Transport)**: ICMPv4/ICMPv6 messages, UDP datagrams, and TCP segments (SYN/ACK/FIN/RST flags, Window Scale, MSS, SACK, Timestamps options).
  - **Layer 7 & Industrial Protocols**: DNS (name pointer decompression, QName decoding, A/AAAA/CNAME/MX/TXT/NS/PTR/SRV resource records), SocketCAN (CAN-over-PCAP frame decoder), Modbus TCP (MBAP header & function codes), and MQTT (Fixed & Variable header, control packet types, topic parsing).
- **TCP Stream Reassembly Engine**:
  - 5-tuple (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `protocol`) `SessionKey` with canonical bidirectional equality and hashing.
  - Out-of-order segment buffer queue and sequence overlap/gap resolution.
  - Continuous stream payload reconstruction and state machine tracking (`LISTEN`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT`, `CLOSED`).
- **Network Traffic Analytics & Anomaly Detector**:
  - Packet count, byte volume, protocol distribution breakdown, min/max/avg packet length.
  - Packet length distribution histogram bins.
  - Round Trip Time (RTT) estimator tracking TCP SYN $\rightarrow$ SYN-ACK deltas.
  - Security Anomaly Detector: IP/TCP/UDP checksum errors, SYN flood suspicion, malformed header lengths.
- **Exporters & CLI Utilities**:
  - Formatted JSON exporter, tabular CSV exporter, and ANSI Terminal summary table formatter.
  - Standalone executable CLI runner (`cmd/main`) and WASM browser interop interface (`src/wasm`).

---

## 🏗️ Architecture & Module Design

```
+-----------------------------------------------------------------------------------+
|                                 cli / wasm / main                                 |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+-----------------------+   +------------------------+   +--------------------------+
|       exporter        |   |        analyzer        |   |       reassembly         |
| (JSON / CSV / Text)   |   | (Stats, RTT, Anomaly)  |   | (5-Tuple, Stream Buffer) |
+-----------------------+   +------------------------+   +--------------------------+
            |                            |                            |
            +----------------------------+----------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                                     layers                                        |
| (Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, UDP, TCP, DNS, CAN, Modbus TCP, MQTT)     |
+-----------------------------------------------------------------------------------+
                                         |
                                         v
+----------------------------------------+------------------------------------------+
|                 pcap                   |                 pcapng                   |
|       (Classic PCAP Reader/Writer)     |        (PCAPNG Block & Option Parser)    |
+----------------------------------------+------------------------------------------+
                                         |
                                         v
+-----------------------------------------------------------------------------------+
|                                     binary                                        |
|          (BinaryReader, BinaryWriter, Endianness, RFC 1071 Checksum, Hex)         |
+-----------------------------------------------------------------------------------+
```

### Module Breakdown

| Package | Purpose |
| :--- | :--- |
| `src/binary` | Endianness handling (`LittleEndian`/`BigEndian`), integer reading/writing, RFC 1071 checksum, hex dumpers |
| `src/pcap` | PCAP classic global header, packet header, streaming packet reader & writer |
| `src/pcapng` | PCAPNG block parser (SHB, IDB, EPB, SPB, ISB, NRB) and TLV options parser |
| `src/layers` | L2-L7 protocol dissectors (Ethernet, VLAN, ARP, IPv4, IPv6, ICMP, UDP, TCP, DNS, CAN, Modbus, MQTT) |
| `src/reassembly` | Canonical 5-tuple session keys, out-of-order segment buffer, sequence overlap resolution, stream reassembly |
| `src/analyzer` | Traffic volume statistics, protocol distribution, length histograms, RTT estimation, security anomaly detection |
| `src/exporter` | Formatted JSON exporter, tabular CSV exporter, ANSI terminal summary table renderer |
| `src/cli` | Command line argument parsing and execution pipeline runner |
| `src/wasm` | WebAssembly bindings for embedding packet parsing into web interfaces |
| `cmd/main` | Executable entry point |

---

## ⚡ Quick Start & Usage

### 1. Build and Run Tests

Ensure you have the MoonBit toolchain installed (`moon` 0.10.4+):

```bash
# Check compiler warnings and syntax strictness
moon check --deny-warn

# Code formatting check
moon fmt

# Run comprehensive test suite
moon test

# Execute main application
moon run cmd/main
```

### 2. Basic Code Examples

#### Reading a Classic PCAP File

```moonbit
import "cghyyrrt/moonbit-pcap/src/pcap"

fn process_pcap(bytes : Bytes) {
  let reader_opt = @pcap.PcapReader::new(bytes)
  match reader_opt {
    Some(reader) => {
      let header = reader.get_global_header()
      println("LinkType: \{header.network}, Version: \{header.version_major}.\{header.version_minor}")
      let packets = reader.read_all()
      for pkt in packets {
        println("Packet timestamp: \{pkt.timestamp}, len: \{pkt.payload.length()}")
      }
    }
    None => println("Failed to parse PCAP header")
  }
}
```

#### Parsing IPv4 & TCP Headers

```moonbit
import "cghyyrrt/moonbit-pcap/src/layers"
import "cghyyrrt/moonbit-pcap/src/binary"

fn analyze_packet(payload : Bytes) {
  match @layers.parse_ethernet(payload) {
    Some(eth) => {
      if eth.ethertype == 0x0800U { // IPv4
        match @layers.parse_ipv4(eth.payload) {
          Some(ip) => {
            println("Src IP: \{@binary.ip4_to_string(ip.src_ip)} -> Dst IP: \{@binary.ip4_to_string(ip.dst_ip)}")
            if ip.protocol == b'\x06' { // TCP
              match @layers.parse_tcp(ip.payload) {
                Some(tcp) => println("TCP Src Port: \{tcp.src_port}, Dst Port: \{tcp.dst_port}, SYN: \{tcp.flag_syn}")
                None => ()
              }
            }
          }
          None => ()
        }
      }
    }
    None => ()
  }
}
```

#### Out-of-Order TCP Stream Reassembly

```moonbit
import "cghyyrrt/moonbit-pcap/src/reassembly"

fn reassemble_demo() {
  let key = @reassembly.SessionKey::new("10.0.0.1", 12345U, "10.0.0.2", 80U)
  let reassembler = @reassembly.TcpStreamReassembler::new(key)
  reassembler.set_initial_seq(1000U)

  let seg1 = Bytes::from_array([b'H', b'e', b'l', b'l', b'o'])
  let seg2 = Bytes::from_array([b' ', b'W', b'o', b'r', b'l', b'd'])

  // Arrive out of order: seq=1005 first, then seq=1000
  reassembler.add_segment(1005U, seg2, 1.1)
  reassembler.add_segment(1000U, seg1, 1.0)

  let payload = reassembler.get_data()
  // Payload reconstructed as: "Hello World"
}
```

---

## 🏆 Open Source Contest 2026 (OSC 2026) Project Info

- **Project Name**: `moonbit-pcap` (MoonBit 网络报文捕获与协议分析库)
- **Contest**: Open Source Contest 2026 (OSC 2026) — MoonBit Track
- **Author & Single Contributor**: `cghyyrrt` (`cghyyrrt@users.noreply.github.com`)
- **Code Scale**: > 17,000 lines of MoonBit code (`.mbt`) across 10 subpackages.
- **Git Commit History**: > 10 structured, atomic commits tracking feature milestones.
- **Dual Remote Sync**: Synchronized with both GitHub (`github.com/cghyyrrt/moonbit-pcap`) and GitLink (`gitlink.org.cn/cghyyrrt/moonbit-pcap`).

---

## 📜 License

Distributed under the Apache License 2.0. See [`LICENSE`](LICENSE) for details.
