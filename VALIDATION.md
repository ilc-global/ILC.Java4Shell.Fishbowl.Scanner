# Windows validation checklist — Scan-Java4Shell.ps1

Run on a real Windows host (ideally with a Fishbowl install) before pushing.
Tested so far on Windows PowerShell 5.1 (v5.1.26100) via WSL interop.

## Status (2026-11-17, dev box: AMD Ryzen 7 7840U)
- [x] CPU gate reads `AVX-512 VBMI: PRESENT` (AMD Zen 4 heuristic fixed for mobile suffix).
- [x] Gate 3 finds all 8 installs; JRE-aware split works: Java 8 installs (2024.4,
      2025.1) → `[n/a]`; Java 21 installs (2026.5–2026.10) → `[UNMITIGATED]` (42 files).
- [x] Version parse verified against real bundled `release` files (1.8.0_181, 21.0.x).
- [x] Verdict EXPOSED, exit code 2.
- [x] `-Fix -Yes` on a throwaway copy: flag appended, `.bak` written, CRLF preserved,
      idempotent re-run reports "nothing to do", verdict flips to mitigated.
- [ ] **Gate 2 live-process branch** — NOT yet exercised against a running Fishbowl
      service (none running on the dev box). The `release`-file parse it depends on
      is verified; the CIM process enumeration is not.

## Remaining checks (do on a host with the Fishbowl service running)
- [ ] Start the Fishbowl Server service; run the script; confirm a `java.exe` row
      appears with correct PID, `jre\bin\java.exe` path, `java 21.0.x [VULNERABLE JRE]`,
      app label "Fishbowl".
- [ ] If CIM is blocked/denied, the script prints "(none running, or process list
      unavailable)" rather than throwing.
- [ ] Start a non-Fishbowl JVM (if available) → the "non-Fishbowl JVM" NOTE appears.
- [ ] Elevated vs non-elevated: confirm `-Fix` under Program Files needs admin and
      fails cleanly (per-file "FAILED … Access … denied") without admin.
- [ ] Real apply on a maintenance window: `-Fix`, restart service, confirm clients
      connect, rescan shows mitigated.

## Known limits
- CPU gate is a heuristic; Intel server CPUs often read Unknown. Document coreinfo.
- Only tested via WSL interop so far; a native double-click / RDP run is worth one pass.
