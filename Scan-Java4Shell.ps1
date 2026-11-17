#requires -Version 5.1
<#
.SYNOPSIS
    Triage a Windows host for Java4Shell (CVE-2026-114938) and suggest/apply mitigation.

.DESCRIPTION
    Checks three gates:
      1. CPU silicon      - best-effort AVX-512 VBMI read (the bug only fires on VBMI CPUs).
      2. Running JVMs       - java.exe/javaw.exe processes and their bundled JRE version.
      3. Fishbowl configs   - *.vmoptions under Fishbowl* installs; mitigated or not.

    A host is EXPOSED when a vulnerable JRE (>= 17.0.6) or an unmitigated Fishbowl
    config exists on AVX-512-VBMI silicon. The mitigation flag '-XX:-UseBASE64Intrinsics'
    is harmless to apply regardless, so -Fix can patch unmitigated .vmoptions files
    (a .bak backup is written first).

.PARAMETER Root
    One or more directories to scan for Fishbowl*/*.vmoptions.
    Default: 'C:\Program Files' and 'C:\Program Files (x86)'.

.PARAMETER Fix
    Append '-XX:-UseBASE64Intrinsics' to unmitigated Fishbowl .vmoptions files.

.PARAMETER Yes
    Apply -Fix without the confirmation prompt.

.EXAMPLE
    .\Scan-Java4Shell.ps1
    .\Scan-Java4Shell.ps1 -Fix
    .\Scan-Java4Shell.ps1 -Root 'D:\Apps' -Fix -Yes

.NOTES
    CVE details come from the researchers' advisory (calif.io/java4shell); verify
    against the official Oracle + OpenJDK advisories. Writing .vmoptions under
    Program Files requires an elevated (Administrator) PowerShell. Exit code 2 = EXPOSED.
#>
[CmdletBinding()]
param(
    [string[]] $Root,
    [switch]   $Fix,
    [switch]   $Yes
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$script:MitigationFlag = '-XX:-UseBASE64Intrinsics'
$script:Cve            = 'CVE-2026-114938'
# JDK feature/update level where the buggy Base64 intrinsic was introduced.
$script:Floor          = [Version]'17.0.6'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function ConvertTo-JavaVersion {
    param([string] $Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    # Keep the leading numeric/dot run: "21.0.13+9" -> "21.0.13", "1.8.0_511" -> "1.8.0"
    $m = [regex]::Match($Raw.Trim(), '^[0-9]+(\.[0-9]+)*')
    if (-not $m.Success) { return $null }
    $parts = $m.Value.Split('.')
    $a = [int]$parts[0]
    $b = if ($parts.Count -ge 2) { [int]$parts[1] } else { 0 }
    $c = if ($parts.Count -ge 3) { [int]$parts[2] } else { 0 }
    # Legacy "1.8" scheme -> feature version is the second component.
    if ($a -eq 1) { $major = $b; $minor = $c; $patch = 0 }
    else          { $major = $a; $minor = $b; $patch = $c }
    [pscustomobject]@{
        Major   = $major
        Minor   = $minor
        Patch   = $patch
        Raw     = $Raw.Trim()
        Version = [Version]("{0}.{1}.{2}" -f $major, $minor, $patch)
    }
}

function Get-Affection {
    param($Ver)   # object from ConvertTo-JavaVersion, or $null
    if ($null -eq $Ver)        { return 'Unknown' }
    if ($Ver.Major -eq 8)      { return 'Java8Special' }   # only Oracle 8u511b33-perf
    if ($Ver.Version -ge $script:Floor) { return 'Vulnerable' }
    return 'NotAffected'
}

function Test-MitigationLine {
    param([string] $Line)
    $l = $Line.Trim()
    if ($l -eq $script:MitigationFlag) { return $true }
    # -XX:UseAVX=0|1|2 drops the AVX-512 VBMI path wholesale.
    if ($l -match '^-XX:UseAVX=([012])\s*$') { return $true }
    return $false
}

function Get-AppLabel {
    param([string] $CmdLine)
    if ([string]::IsNullOrEmpty($CmdLine)) { return '' }
    $lc = $CmdLine.ToLowerInvariant()
    $map = [ordered]@{
        'fishbowl'      = 'Fishbowl'
        'eve.jar'       = 'Fishbowl server (eve)'
        'fb-rest'       = 'Fishbowl REST API'
        'tomcat'        = 'Tomcat'
        'jenkins'       = 'Jenkins'
        'elasticsearch' = 'Elasticsearch'
        'solr'          = 'Solr'
        'keycloak'      = 'Keycloak'
        'confluence'    = 'Confluence'
        'jira'          = 'Jira'
    }
    $hits = @()
    foreach ($k in $map.Keys) {
        if ($lc.Contains($k) -and ($hits -notcontains $map[$k])) { $hits += $map[$k] }
    }
    return ($hits -join ', ')
}

# ---------------------------------------------------------------------------
# Gate 1: CPU
# ---------------------------------------------------------------------------

function Test-Cpu {
    $name = 'unknown'
    try { $name = (Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1).Name.Trim() } catch {}

    # Best-effort only. PowerShell 5.1 (.NET Framework) cannot query AVX-512 VBMI
    # directly, so we infer from the CPU family and otherwise report Unknown.
    #   AMD Zen 4+ (Ryzen 7000/8000/9000, EPYC 9004/9005) carry AVX-512 VBMI.
    #   Intel Ice Lake-SP and newer Xeons carry it, but the brand string rarely
    #   names the microarch, so Intel is usually left Unknown.
    $vbmi = $null  # $true / $false / $null(unknown)

    if ($name -match 'AMD') {
        # Model numbers run \b[digit]NNN with an optional letter suffix (e.g. 7840U,
        # 9950X3D), so we anchor the leading boundary only, not a trailing one.
        if ($name -match 'Ryzen.*\b[7-9]\d{3}' -or $name -match 'EPYC\s*9\d{3}' -or $name -match 'Ryzen.*\bAI\b') {
            $vbmi = $true   # Zen 4+ (Ryzen 7000/8000/9000, AI 300, EPYC 9004/9005)
        } elseif ($name -match 'Ryzen.*\b[1-6]\d{3}' -or $name -match 'EPYC\s*7\d{3}') {
            $vbmi = $false  # Zen 1-3 / early EPYC: no AVX-512
        }
    } elseif ($name -match 'Intel') {
        # Consumer 12th-gen+ (Alder/Raptor Lake) ship with AVX-512 fused off.
        if ($name -match 'i[3579]-1[2-9]\d{3}') { $vbmi = $false }
        # Xeon Ice Lake+ generally has it, but we cannot tell the gen from the name.
    }

    [pscustomobject]@{ Name = $name; Vbmi = $vbmi }
}

# ---------------------------------------------------------------------------
# Gate 2: running JVMs
# ---------------------------------------------------------------------------

function Get-JreVersionFromExe {
    param([string] $ExePath)
    if ([string]::IsNullOrEmpty($ExePath)) { return $null }
    try {
        # <jre>\bin\java.exe -> <jre>\release
        $jre     = Split-Path (Split-Path $ExePath -Parent) -Parent
        $release = Join-Path $jre 'release'
        if (Test-Path -LiteralPath $release) {
            foreach ($line in Get-Content -LiteralPath $release) {
                if ($line -match '^JAVA_VERSION="?([^"]+)"?') {
                    return (ConvertTo-JavaVersion $Matches[1])
                }
            }
        }
    } catch {}
    return $null
}

function Get-RunningJava {
    $procs = @()
    try {
        $raw = Get-CimInstance Win32_Process -Filter "Name='java.exe' OR Name='javaw.exe'" -ErrorAction Stop
    } catch {
        return @()   # CIM unavailable; caller treats as "none / unavailable"
    }
    foreach ($p in $raw) {
        $ver = Get-JreVersionFromExe $p.ExecutablePath
        $procs += [pscustomobject]@{
            Pid       = $p.ProcessId
            Exe       = $p.ExecutablePath
            CmdLine   = $p.CommandLine
            Version   = $ver
            Affection = (Get-Affection $ver)
            App       = (Get-AppLabel $p.CommandLine)
        }
    }
    return $procs
}

# ---------------------------------------------------------------------------
# Gate 3: Fishbowl .vmoptions
# ---------------------------------------------------------------------------

function Get-FishbowlVmoptions {
    param([string[]] $Roots)
    $results = @()
    foreach ($root in $Roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $fbDirs = Get-ChildItem -LiteralPath $root -Directory -ErrorAction SilentlyContinue |
                  Where-Object { $_.Name -like 'Fishbowl*' }
        foreach ($d in $fbDirs) {
            # Resolve the install's bundled JRE so we only flag installs whose Java
            # is actually affected (e.g. Fishbowl on Java 8 is NOT vulnerable).
            $jreVer = $null
            $releasePath = Join-Path $d.FullName 'jre\release'
            if (Test-Path -LiteralPath $releasePath) {
                foreach ($line in Get-Content -LiteralPath $releasePath) {
                    if ($line -match '^JAVA_VERSION="?([^"]+)"?') { $jreVer = ConvertTo-JavaVersion $Matches[1]; break }
                }
            }
            $jreAff  = Get-Affection $jreVer
            $jreStr  = if ($jreVer) { $jreVer.Raw } else { 'unknown' }

            $files = Get-ChildItem -LiteralPath $d.FullName -Recurse -Filter '*.vmoptions' -ErrorAction SilentlyContinue
            foreach ($f in $files) {
                $mitigated = $false
                try {
                    foreach ($line in Get-Content -LiteralPath $f.FullName) {
                        if (Test-MitigationLine $line) { $mitigated = $true; break }
                    }
                } catch {}
                $results += [pscustomobject]@{
                    Path          = $f.FullName
                    Mitigated     = $mitigated
                    Install       = $d.Name
                    JreVersion    = $jreStr
                    JreAffection  = $jreAff   # Vulnerable / Java8Special / NotAffected / Unknown
                }
            }
        }
    }
    return ($results | Sort-Object Path -Unique)
}

function Invoke-Fix {
    param($Unmitigated, [switch] $NoPrompt)
    if ($Unmitigated.Count -eq 0) {
        Write-Host "-Fix: nothing to do, all discovered files already mitigated." -ForegroundColor Green
        return
    }
    Write-Host ""
    Write-Host "-Fix: will append '$($script:MitigationFlag)' (after a .bak backup) to:" -ForegroundColor Yellow
    $Unmitigated | ForEach-Object { Write-Host "   $($_.Path)" }
    if (-not $NoPrompt) {
        $ans = Read-Host "Proceed? [y/N]"
        if ($ans -notmatch '^(y|yes)$') { Write-Host "Aborted. No files changed."; return }
    }
    foreach ($v in $Unmitigated) {
        try {
            $bak = "$($v.Path).bak"
            if (-not (Test-Path -LiteralPath $bak)) {
                Copy-Item -LiteralPath $v.Path -Destination $bak -ErrorAction Stop
            }
            Add-Content -LiteralPath $v.Path -Value $script:MitigationFlag -ErrorAction Stop
            Write-Host "   patched $($v.Path)" -ForegroundColor Green
        } catch {
            Write-Host "   FAILED  $($v.Path): $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host "Done. Restart the Fishbowl Server service for the flag to take effect." -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if (-not $Root -or $Root.Count -eq 0) {
    $Root = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}") | Where-Object { $_ }
}

Write-Host "==================================================================" -ForegroundColor White
Write-Host " Java4Shell scanner (PowerShell)  -  $script:Cve"
Write-Host "==================================================================" -ForegroundColor White
Write-Host ""

# Gate 1
$cpu = Test-Cpu
Write-Host "[1] CPU silicon"
Write-Host "    model : $($cpu.Name)"
switch ($cpu.Vbmi) {
    $true  { Write-Host "    AVX-512 VBMI : PRESENT  -> vulnerable intrinsic CAN fire here" -ForegroundColor Red }
    $false { Write-Host "    AVX-512 VBMI : absent   -> intrinsic bug NOT triggerable on this CPU" -ForegroundColor Green }
    default {
        Write-Host "    AVX-512 VBMI : UNKNOWN (PowerShell cannot read it precisely)" -ForegroundColor Yellow
        Write-Host "                   Treat as possibly vulnerable. The mitigation flag is"
        Write-Host "                   harmless to apply regardless of CPU."
    }
}
Write-Host ""

# Gate 2
Write-Host "[2] Running Java processes"
$procs = @(Get-RunningJava)
$anyVulnJvm = $false
$nonFishbowlVuln = $false
if ($procs.Count -eq 0) {
    Write-Host "    (none running, or process list unavailable)"
} else {
    foreach ($p in $procs) {
        $tag = switch ($p.Affection) {
            'Vulnerable'   { $anyVulnJvm = $true; 'VULNERABLE JRE' }
            'Java8Special' { 'Java 8 (only Oracle 8u511b33-perf affected)' }
            'NotAffected'  { 'version OK' }
            default        { 'version UNKNOWN (verify manually)' }
        }
        $vstr = if ($p.Version) { $p.Version.Raw } else { 'unknown' }
        $color = if ($p.Affection -eq 'Vulnerable') { 'Red' } elseif ($p.Affection -eq 'NotAffected') { 'Green' } else { 'Yellow' }
        Write-Host ("    pid {0,-7} java {1,-12} [{2}]" -f $p.Pid, $vstr, $tag) -ForegroundColor $color
        if ($p.App) { Write-Host "              app  : $($p.App)" }
        if ($p.Exe) { Write-Host "              exe  : $($p.Exe)" }
        $isFishbowl = $p.App.ToLowerInvariant().Contains('fishbowl')
        if (($p.Affection -eq 'Vulnerable' -or $p.Affection -eq 'Unknown') -and -not $isFishbowl) {
            $nonFishbowlVuln = $true
            Write-Host "              NOTE : non-Fishbowl JVM - may be vulnerable; this tool" -ForegroundColor Yellow
            Write-Host "                     does not patch it. Add '$script:MitigationFlag' to" -ForegroundColor Yellow
            Write-Host "                     its own launch args / JAVA_TOOL_OPTIONS." -ForegroundColor Yellow
        }
    }
    if ($nonFishbowlVuln) {
        Write-Host "    (see per-process NOTE: non-Fishbowl JVMs need manual mitigation)"
    }
}
Write-Host ""

# Gate 3
Write-Host "[3] Fishbowl .vmoptions files"
$vmopts = @(Get-FishbowlVmoptions -Roots $Root)
# A file needs mitigation only when its install's bundled JRE is itself affected
# (Vulnerable, or Unknown as a safe default). Java 8 installs are not vulnerable.
$needsFix = { param($v) (-not $v.Mitigated) -and ($v.JreAffection -eq 'Vulnerable' -or $v.JreAffection -eq 'Unknown') }
$unmitigated = @($vmopts | Where-Object { & $needsFix $_ })
if ($vmopts.Count -eq 0) {
    Write-Host "    (no Fishbowl .vmoptions found under: $($Root -join ', '))"
} else {
    foreach ($v in $vmopts) {
        $jre = "JRE $($v.JreVersion)"
        if ($v.JreAffection -eq 'Java8Special' -or $v.JreAffection -eq 'NotAffected') {
            Write-Host "    [n/a]         $($v.Path)  ($jre - not vulnerable)" -ForegroundColor DarkGray
        } elseif ($v.Mitigated) {
            Write-Host "    [mitigated]  $($v.Path)  ($jre)" -ForegroundColor Green
        } else {
            Write-Host "    [UNMITIGATED] $($v.Path)  ($jre)" -ForegroundColor Red
        }
    }
}
Write-Host ""

# Verdict
$anyUnmitigated = $unmitigated.Count -gt 0
# Treat Unknown CPU as "possibly vulnerable" for the verdict.
$cpuMaybe = ($cpu.Vbmi -ne $false)
$exposed  = $cpuMaybe -and ($anyVulnJvm -or $anyUnmitigated)

Write-Host "------------------------------------------------------------------" -ForegroundColor White
if ($exposed) {
    if ($cpu.Vbmi -eq $true) {
        Write-Host " VERDICT: EXPOSED" -ForegroundColor Red
    } else {
        Write-Host " VERDICT: POTENTIALLY EXPOSED (CPU unconfirmed)" -ForegroundColor Yellow
    }
    Write-Host " A vulnerable path exists on this host. Apply mitigation."
} elseif ($cpu.Vbmi -eq $false) {
    Write-Host " VERDICT: NOT TRIGGERABLE on this CPU" -ForegroundColor Green
    Write-Host " This silicon lacks AVX-512 VBMI. Still mitigate before moving the"
    Write-Host " install to newer hardware (Intel Ice Lake+/AMD Zen 4+)."
} else {
    Write-Host " VERDICT: likely mitigated / no vulnerable JVM observed" -ForegroundColor Green
    Write-Host " Re-run after any Fishbowl or JRE update to confirm."
}
Write-Host "------------------------------------------------------------------" -ForegroundColor White
Write-Host ""

Write-Host "Mitigation (per JVM, zero functional impact):"
Write-Host "  Add this line to each Fishbowl *server* .vmoptions and restart the service:"
Write-Host "      $script:MitigationFlag"
Write-Host "  Durable fix: update the bundled JRE to a patched build once Fishbowl ships one."
Write-Host "  Verify CPU precisely: Sysinternals 'coreinfo64 -f' (look for AVX512_VBMI),"
Write-Host "  or the companion Rust scanner."
Write-Host ""

if ($Fix) {
    Invoke-Fix -Unmitigated $unmitigated -NoPrompt:$Yes
} elseif ($anyUnmitigated) {
    Write-Host "Re-run with -Fix to append the flag to the $($unmitigated.Count) unmitigated file(s) above."
}

if ($exposed) { exit 2 } else { exit 0 }
