# Java4Shell Fishbowl Scanner

A single PowerShell script that triages a Windows host for **Java4Shell
(CVE-2026-114938)** — the AVX-512 VBMI Base64 intrinsic memory-corruption bug in
OpenJDK 17.0.6+ / 21 / 25 — and can apply the mitigation to Fishbowl installs.

No install, no compiler, no dependencies: it runs on the Windows PowerShell 5.1
that ships with every supported version of Windows.

> CVE details come from the researchers' advisory (<https://calif.io/java4shell/>).
> Verify specifics against the official Oracle and OpenJDK advisories.

## What it checks

| Gate | How |
|------|-----|
| **1. CPU silicon** | Best-effort AVX-512 VBMI read from the CPU model. PowerShell 5.1 can't query it precisely, so unknown CPUs are treated as *possibly* vulnerable. The mitigation flag is harmless to apply either way. |
| **2. Running JVMs** | Lists `java.exe`/`javaw.exe` via CIM, reads each JRE's `release` file, flags any version ≥ 17.0.6. Non-Fishbowl JVMs are noted (not auto-patched). |
| **3. Fishbowl installs** | Scans `Fishbowl*` installs for `*.vmoptions`, **and reads each install's bundled JRE** so it only flags installs on an affected Java. Fishbowl on Java 8 is reported `[n/a] – not vulnerable`. |

**Verdict:** `EXPOSED` when an affected JRE or an unmitigated affected-JRE Fishbowl
config exists on AVX-512-VBMI (or unconfirmed) silicon. Exit code `2` = exposed, else `0`.

## Usage

Open an **elevated** (Administrator) PowerShell — writing `.vmoptions` under
`C:\Program Files` needs it.

```powershell
# Read-only scan + mitigation advice
.\Scan-Java4Shell.ps1

# Scan, then prompt before patching unmitigated (affected-JRE) files
.\Scan-Java4Shell.ps1 -Fix

# Patch without the prompt
.\Scan-Java4Shell.ps1 -Fix -Yes

# Scan an extra location
.\Scan-Java4Shell.ps1 -Root 'D:\Apps'
```

If the script is blocked by execution policy, run it without changing machine policy:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Scan-Java4Shell.ps1
```

## What `-Fix` does

Appends `-XX:-UseBASE64Intrinsics` to each unmitigated `.vmoptions` whose install
runs an affected JRE, after writing a one-time `<file>.vmoptions.bak` backup. It is
idempotent (re-running reports "nothing to do"). **Restart the Fishbowl Server
service afterward** for the flag to take effect.

`-XX:UseAVX=2` in a file is also recognized as already-mitigated; the script only
ever writes `-XX:-UseBASE64Intrinsics`.

## Mitigation summary

- **Stopgap (safe, ~zero perf cost):** add `-XX:-UseBASE64Intrinsics` to each
  Fishbowl *server* `.vmoptions` and restart the service. That's what `-Fix` does.
- **Durable fix:** update the bundled JRE to a patched build once Fishbowl ships one.
- **Can't patch yet:** restrict the Fishbowl ports (28192 + the REST/web port) to
  trusted networks/VPN in the meantime.

## Confirming the CPU precisely

PowerShell can't read AVX-512 VBMI directly. To be certain on a given host, use
Sysinternals **coreinfo** (`coreinfo64 -f`, look for `AVX512_VBMI`), or check the
CPU model against Intel Ice Lake-SP+ / AMD Zen 4+.

## Caveats

- Gate 1 is a heuristic; Intel server CPUs often read as *Unknown* because the
  brand string doesn't name the microarchitecture. Treat Unknown as possibly
  vulnerable.
- The intrinsic is JVM-wide: non-Fishbowl Java apps on the host (Jenkins,
  Elasticsearch, etc.) need the same flag set their own way — the script lists them
  but does not patch them.
- Run on each **server** that hosts a JVM; scanning one box does not clear another.
