# Reproducible benchmark

The benchmark uses a fixed 42-byte Ethernet/IPv4/UDP frame and MoonBit's
stable `core/bench` monotonic clock. It measures the real parser invocation;
the output is not a hand-written performance claim.

Run it with:

```text
moon bench benchmarks
```

Verified locally on 2026-08-21 with MoonBit `0.1.20260814` on Windows:

```text
ethernet_ipv4_udp_parse  472.67 ns ± 28.90 ns   435.88 ns … 532.31 ns  in 10 × 100000 runs
```

Results are machine-dependent and should not be compared across runners
without the same toolchain, target, and operating system.
