# MoonBit PCAP Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend `moonbit-pcap` with useful industrial protocol parsing, strong boundary coverage, reproducible benchmarks, current MoonBit CI, and publish-ready documentation while exceeding 8,000 verified handwritten `.mbt` lines.

**Architecture:** Keep the existing package boundaries. Add protocol-specific files under `src/layers`, shared byte/CRC helpers under `src/binary` only when an existing helper cannot be reused, and tests beside each package. Keep benchmark generation deterministic and separate from library APIs. Treat `_build` as generated output and exclude it from all source metrics.

**Tech Stack:** MoonBit stable toolchain, MoonBit standard library, GitHub Actions, Apache-2.0, Mooncakes package publishing.

## Global Constraints

- Do not modify `8月黑客松项目申报书.md` or `project_application.md`.
- Do not claim a source count or benchmark number until a fresh command produces it.
- Do not add external C dependencies.
- Do not place credentials in tracked files or commit history.
- README must not mention applicant, completion review, sole contributor, or internal contest evidence.
- Every new parser behavior starts with a failing test, then minimal implementation, then refactor.

---

### Task 1: Establish the baseline and metric command

**Files:**
- Create: `scripts/source-metrics.ps1`
- Modify: `.gitignore` only if generated benchmark/build output needs an ignore rule
- Test: existing `moon check` and `moon test`

**Interfaces:**
- Produces a PowerShell metric command that counts only `src/**/*.mbt` and `cmd/**/*.mbt`, separating `_test.mbt` from production files and reporting raw/non-empty/code lines.

- [ ] **Step 1: Write the metric script**

The script must resolve the repository root from its own location, enumerate only `src` and `cmd`, exclude generated paths, and print file count, total lines, production lines, test lines, non-empty lines and comment-free lines. It must exit non-zero if the expected source roots are missing.

- [ ] **Step 2: Run the baseline metric**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/source-metrics.ps1`

Expected: reports the audited baseline near 4,921 total handwritten lines and does not count `_build`.

- [ ] **Step 3: Run baseline tests**

Run: `moon check --deny-warn; moon test`

Expected: exit code 0 and 43 passing tests before feature changes.

- [ ] **Step 4: Commit**

```text
git add scripts/source-metrics.ps1
git commit -m "chore: add reproducible source metrics"
```

### Task 2: Add EtherNet/IP encapsulation parsing

**Files:**
- Create: `src/layers/ethernet_ip.mbt`
- Create: `src/layers/ethernet_ip_test.mbt`
- Modify: `src/layers/moon.pkg` only if package declarations require it

**Interfaces:**
- Produces `EthernetIpHeader`, `EthernetIpCommand`, `EthernetIpEncapsulation::parse(Bytes)`, `EthernetIpEncapsulation::is_valid()`, and payload accessors following the existing `Option`-based parser style.
- Supports the 24-byte encapsulation header, little-endian command/session/status/length fields, options, `RegisterSession`, and `SendRRData` payload extraction.

- [ ] **Step 1: Write failing tests**

Cover a valid RegisterSession frame, a valid SendRRData frame, empty input, 23-byte truncation, declared payload longer than input, unknown command preservation, and maximum session/status values.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `moon test src/layers -f ethernet_ip_test.mbt`

Expected: compilation/test failure because the parser API is not yet implemented.

- [ ] **Step 3: Implement the minimum parser**

Use existing `@binary.BinaryReader`/endianness helpers where possible. Validate header length before slicing, preserve unknown command values, and never panic on malformed input.

- [ ] **Step 4: Run focused and package tests**

Run: `moon test src/layers`

Expected: all layer tests pass.

- [ ] **Step 5: Format and commit**

Run: `moon fmt`

```text
git add src/layers/ethernet_ip.mbt src/layers/ethernet_ip_test.mbt src/layers/moon.pkg
git commit -m "feat(layers): parse EtherNet/IP encapsulation frames"
```

### Task 3: Add DNP3 link and application parsing

**Files:**
- Create: `src/layers/dnp3.mbt`
- Create: `src/layers/dnp3_test.mbt`
- Modify: `src/binary/crc.mbt` only if a reusable DNP3 CRC helper is absent

**Interfaces:**
- Produces `Dnp3LinkHeader`, `Dnp3TransportHeader`, `Dnp3ApplicationHeader`, `Dnp3ObjectHeader`, `Dnp3Frame::parse(Bytes)`, and explicit validity/CRC status fields.
- Supports start bytes `0x0564`, length/address/control fields, per-block CRC validation, transport FIN/FIR/sequence, application FIR/FIN/sequence, and common binary/analog object headers.

- [ ] **Step 1: Write failing tests**

Cover a valid link frame with correct CRC, invalid start bytes, short link header, invalid length, invalid link CRC, transport sequence wraparound, application control flags, unknown object group/variation, and truncated object data.

- [ ] **Step 2: Run focused tests and verify RED**

Run: `moon test src/layers -f dnp3_test.mbt`

Expected: failure before the parser exists.

- [ ] **Step 3: Implement CRC and bounded parsing**

Implement the protocol CRC table/calculation in a focused helper, split payload into 16-byte blocks plus CRC bytes, and return structured invalid results instead of indexing past input.

- [ ] **Step 4: Run package tests and check warnings**

Run: `moon test src/layers --deny-warn`

Expected: all tests pass with no warnings.

- [ ] **Step 5: Format and commit**

```text
git add src/layers/dnp3.mbt src/layers/dnp3_test.mbt src/binary/crc.mbt
git commit -m "feat(layers): add bounded DNP3 frame parsing"
```

### Task 4: Expand existing parser edge coverage and reusable fixtures

**Files:**
- Create: `src/testkit/fixtures.mbt`
- Create: `src/testkit/moon.pkg`
- Create or modify: focused `*_test.mbt` files under `src/pcap`, `src/pcapng`, `src/layers`, `src/reassembly`, and `src/analyzer`

**Interfaces:**
- Produces deterministic fixture builders for truncated Ethernet/IPv4/IPv6/TCP/DNS/PCAP/PCAPNG data and a small assertion helper set used only by tests.

- [ ] **Step 1: Add failing regression tests**

Add tests for zero-length captures, truncated global/block headers, invalid PCAPNG block lengths and padding, IPv4 IHL/options limits, IPv6 extension-chain truncation, TCP option length zero, DNS pointer loops/out-of-range pointers, overlapping TCP segments, IP fragment gaps, and filter predicates over missing fields.

- [ ] **Step 2: Run targeted tests and verify each new regression fails**

Run the narrowest package command for each changed package; expected failures must be caused by the missing behavior, not test syntax.

- [ ] **Step 3: Implement bounded checks**

Add minimal guards and explicit invalid/empty outcomes while preserving all existing public behavior.

- [ ] **Step 4: Run the full suite**

Run: `moon test --deny-warn`

Expected: zero failures and no warnings.

- [ ] **Step 5: Format and commit**

```text
git add src/testkit src/pcap src/pcapng src/layers src/reassembly src/analyzer
git commit -m "test: cover malformed captures and protocol boundaries"
```

### Task 5: Add a deterministic benchmark runner

**Files:**
- Create: `bench/README.md`
- Create: `bench/benchmark.mbt`
- Create: `bench/moon.pkg`
- Modify: `README.md` after actual benchmark output is collected

**Interfaces:**
- Produces a runnable benchmark entry point that builds a fixed synthetic Ethernet/IPv4/UDP capture, parses it repeatedly, measures elapsed time using verified local MoonBit APIs, and prints `packets`, `bytes`, `successes`, `elapsed_ms`, and `throughput_mib_s`.

- [ ] **Step 1: Add benchmark acceptance test or deterministic output check**

Test the fixture generator separately: fixed packet count, fixed packet length, and stable checksum/length fields.

- [ ] **Step 2: Run the new test and verify RED**

Run: `moon test bench`

Expected: failure because the benchmark package is not implemented.

- [ ] **Step 3: Implement the fixture and runner**

Use only library APIs and a monotonic/time API verified with `moon ide doc` or existing project usage. Avoid reporting a benchmark value in documentation until the command runs locally.

- [ ] **Step 4: Run benchmark and capture evidence**

Run: `moon run bench`

Record the complete output in `bench/README.md` with date, MoonBit version, OS, repetition count, and the exact command.

- [ ] **Step 5: Commit**

```text
git add bench
git commit -m "perf: add reproducible packet parsing benchmark"
```

### Task 6: Reach the verified source target through useful API expansion

**Files:**
- Modify: `src/layers` protocol modules as required by implementation gaps
- Create: focused production modules for protocol field decoding, object iteration, packet classification, and export summaries
- Create: corresponding tests in the owning package

**Interfaces:**
- Produces concrete user-facing helpers needed by the new protocol parsers and benchmark pipeline; no filler modules or generated source.

- [ ] **Step 1: Measure the post-Tasks 2–5 source count**

Run: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/source-metrics.ps1`

- [ ] **Step 2: Identify real missing functionality**

Use existing public APIs and申报书的已规划方向 to choose only additions that improve industrial protocol coverage, packet iteration, malformed-input diagnostics, or exportability. Keep each addition paired with a test.

- [ ] **Step 3: Add tests first for each selected API**

Run each focused test and verify RED before implementation.

- [ ] **Step 4: Implement and refactor**

Keep functions bounded and package ownership clear; run `moon fmt` after each logical group.

- [ ] **Step 5: Re-measure and verify the threshold**

Run the metric script and require total handwritten `.mbt` lines over 8,000 with a recorded production/test split.

- [ ] **Step 6: Commit**

```text
git add src scripts
git commit -m "feat: complete industrial packet analysis surface"
```

### Task 7: Modernize README, CI, and Mooncakes publishing

**Files:**
- Rewrite: `README.md`
- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/publish.yml`
- Modify: `.gitignore` only for generated benchmark artifacts

**Interfaces:**
- README documents actual APIs and measured commands without internal contest language.
- CI checks formatting, all targets, tests, info output and clean formatting diffs on Linux/macOS/Windows.
- Publish workflow is manual, runs prepublish checks, reads a GitHub Secret, writes a temporary credentials file only during the publish step, and removes it in a trap/finally path.

- [ ] **Step 1: Write CI/documentation acceptance checks**

Use repository searches to assert README contains installation/test/license sections and does not contain `申报人`, `结项`, `唯一贡献者`, `OSC 2026`, or `GitLink`.

- [ ] **Step 2: Update CI**

Use the stable installer, `moon version --all`, `moon update`, `moon fmt --check`, `moon check --deny-warn --target all`, `moon test --deny-warn --target all`, `moon info`, and `git diff --exit-code`.

- [ ] **Step 3: Add manual publish workflow**

Use `workflow_dispatch`, least-privilege `contents: read`, `MOONCAKES_TOKEN` as the documented secret name, and no literal token values.

- [ ] **Step 4: Rewrite README from verified facts**

Include package install/import examples only after checking local package metadata; include source metrics and benchmark numbers only from fresh commands.

- [ ] **Step 5: Validate YAML and docs locally**

Run repository searches, `moon fmt --check`, and a YAML parser if available; otherwise use GitHub Actions syntax structure inspection and report the limitation.

- [ ] **Step 6: Commit**

```text
git add README.md .github/workflows/ci.yml .github/workflows/publish.yml
git commit -m "docs(ci): prepare stable checks and Mooncakes publishing"
```

### Task 8: Final verification, self-check, GitHub push, and Mooncakes publish

**Files:**
- No source changes expected; update `progress.md` with evidence.

**Interfaces:**
- Produces a complete evidence table covering structure, README, LICENSE, commit history, default branch, source metrics, tests, CI files, GitHub remote, and Mooncakes package metadata.

- [ ] **Step 1: Run the complete local verification**

Run:

```text
moon fmt --check
moon check --deny-warn --target all
moon test --deny-warn --target all
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/source-metrics.ps1
moon run bench
git diff --check
```

- [ ] **Step 2: Run the manual osc2026-guide-equivalent checklist**

Inspect `rg --files`, README forbidden terms, LICENSE, `git log`, `git branch -a -vv`, `git remote -v`, default branch, CI workflow contents, and source metric output. Record every result in `progress.md`.

- [ ] **Step 3: Review GitHub state**

Use `gh auth status`, `gh repo view cghyyrrt/moonbit-pcap`, and `git ls-remote --symref origin HEAD` without exposing credentials. Push only after all local checks pass.

- [ ] **Step 4: Push GitHub main**

Run: `git push origin main`

Expected: GitHub `main` advances to the verified commit history.

- [ ] **Step 5: Publish to Mooncakes**

Run the verified `moon publish` command only after checking `moon login`/credentials status and package metadata. If the registry requires a new version, increment `moon.mod` according to the local toolchain’s validated publishing rules and re-run checks.

- [ ] **Step 6: Final evidence and handoff**

Update `progress.md`, inspect `git status`, and report exact command results. Do not claim completion if any command or remote publish fails.

