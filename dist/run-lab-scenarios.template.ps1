<#
.SYNOPSIS
    Runs detect-content scenarios (artifacts/content/*/tests/*.yml) against a live win10-lab:
    executes each scenario's lab commands on THIS VM and checks that SIEM raises the expected
    incidents.

.DESCRIPTION
    Self-contained file (scenario data embedded by scripts/build_lab_runner.py - see
    D:\__projects\soc_agent\CLAUDE.md #7 "Etap 4.5", and build_lab_runner.py's own docstring).
    Copy this file (dist/run-lab-scenarios.ps1) into the VM and run it THERE - lab commands are
    written to run inside the VM itself, not remotely.

    This script is deliberately ASCII-only in its own code/messages (no literal Cyrillic bytes
    anywhere in the file except inside the base64 blob below, which is pure ASCII too). Embedded
    scenario text (lab notes, fixture content) IS Russian - it survives any encoding mangling
    because it travels as base64 and gets UTF-8-decoded at runtime, independent of how the .ps1
    file itself got transferred/saved. Do not add literal non-ASCII characters to this template -
    a build with mixed BOM/CRLF handling on the way to the VM (antivirus, preview tools, editors)
    can silently corrupt them and break PowerShell's parser before a single line executes.

    ASSUMES the VM already has: the agent installed and running (install-soc-agent.ps1, see
    docs/guide/windows-agent.md), and the SIEM already has detect-content deployed and enabled in
    the main ruleset (scripts/deploy_content.py ... --prune). This script does not check or do
    either of those.

    Lab-line classification (see build_lab_runner.py:classify_line) happens once at build time:
    - [RUN]   looks like executable code (starts with a cmdlet/utility) - will run via
              Invoke-Expression.
    - [NOTE]  free text (a note, a dependency, a reference to another scenario, a "needs a second
              host" requirement) - only printed, never executed or parsed.
    - [DESTRUCTIVE] the fixture text explicitly requires a VM snapshot ("Only on a VM snapshot:" /
              "Rollback:" in the original Russian fixtures) - RUN lines like this are blocked
              until you pass -ConfirmDestructive.
    This classification is a heuristic (based on how the line starts) - it does not replace
    reading the script's own output: a [NOTE] line can still contain something worth running BY
    HAND (e.g. "Defender will block this ... then Add-MpPreference -ExclusionPath ...") - read
    what gets printed, don't rely on auto-run alone.

.PARAMETER SiemUrl
    SIEM address as seen from the VM. Default is the Host-Only address from windows-vm-lab.md #0.

.PARAMETER Source
    Name of the streaming source (SIEM UI tab "Source data") this VM's agent is registered as -
    the same value used when installing the agent. Used for READING ONLY
    (GET /incidents?source_batch=...) - no token needed.

.PARAMETER Domain
    Limit the run to specific domains (auth, recon, execution, ...). Repeatable.

.PARAMETER Scenario
    Limit the run to specific scenarios (SCE_...). Repeatable.

.PARAMETER FromScenario
    Resume the run starting at this scenario (build order) - continue a multi-wave pass.

.PARAMETER ConfirmDestructive
    Allow scenarios flagged [DESTRUCTIVE] to run (you already took a VM snapshot). Without this
    flag such scenarios are shown but skipped.

.PARAMETER Yes
    Do not ask for confirmation before EACH ordinary (non-destructive) scenario. Destructive
    scenarios always ask separately, regardless of this flag.

.PARAMETER TimeoutSec
    How long to wait for the expected incidents to appear after running a scenario (polled every
    5 seconds). Default 25s: the ingest worker flushes every 5s and correlations are evaluated
    right after that flush, so an incident that is going to appear appears within a few seconds.
    Raise it only for correlations whose window itself is long.

.PARAMETER ListOnly
    Only print the plan (which scenarios, what status) without executing anything and without any
    network calls.

.EXAMPLE
    .\run-lab-scenarios.ps1 -Source win10-lab -ListOnly
    .\run-lab-scenarios.ps1 -Source win10-lab -Domain recon,auth -Yes
    .\run-lab-scenarios.ps1 -Source win10-lab -Domain impact -ConfirmDestructive
    .\run-lab-scenarios.ps1 -Source win10-lab -FromScenario SCE_Exec_Download_Then_Execute
#>
param(
    [string]$SiemUrl = "http://192.168.56.1:8000",
    [Parameter(Mandatory = $true)][string]$Source,
    [string[]]$Domain,
    [string[]]$Scenario,
    [string]$FromScenario,
    [switch]$ConfirmDestructive,
    [switch]$Yes,
    [int]$TimeoutSec = 25,
    [switch]$ListOnly
)

$ErrorActionPreference = "Continue"

# Cyrillic content decoded from the base64 blob below prints correctly regardless of the
# console's own default codepage (a common mismatch on RU-locale Windows, see CLAUDE.md's
# app/logging_setup.py rationale for the same class of issue on the server side).
try {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $OutputEncoding = [System.Text.Encoding]::UTF8
} catch {}

# Scenario data (JSON: [{domain, scenario, expected:[...], destructive, needs_second_host, order,
# lines:[{text,kind,destructive,needs_second_host}]}]), base64(UTF8-JSON) - embedded at build
# time, see scripts/build_lab_runner.py. Base64 is pure ASCII: unlike a raw UTF-8 literal, it
# cannot be corrupted by a missing BOM or a CRLF->LF rewrite anywhere on the way to the VM.
$EmbeddedScenariosB64 = $null          # @@EMBED:scenarios.json.b64@@

if (-not $EmbeddedScenariosB64) {
    Write-Error "Not built via scripts/build_lab_runner.py - scenario data is not embedded. Run dist/run-lab-scenarios.ps1, not this template."
    exit 1
}
$scenariosJson = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EmbeddedScenariosB64))
$AllScenarios = $scenariosJson | ConvertFrom-Json

Write-Host "SIEM: $SiemUrl   Source: $Source   Scenarios in set: $($AllScenarios.Count)" -ForegroundColor Cyan
if (-not $ListOnly) {
    try {
        $null = Invoke-RestMethod "$SiemUrl/health" -TimeoutSec 10
        Write-Host "SIEM is reachable." -ForegroundColor Green
    } catch {
        Write-Error "SIEM unreachable at $SiemUrl (see docs/guide/windows-vm-lab.md #0 - network/firewall). $_"
        exit 1
    }
}

# Split comma-joined values by hand: when the script is started as `powershell -File script.ps1
# -Domain recon,execution`, PowerShell passes arguments as LITERAL strings, so [string[]]$Domain
# ends up as one element "recon,execution" and matches no domain at all - the run then dies with
# "No scenarios left after filtering" and looks like a data problem. Called the normal way
# (.\script.ps1 -Domain recon,execution) the comma is parsed by PowerShell itself and this is a
# no-op.
$Domain = @($Domain | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$Scenario = @($Scenario | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$scenarios = $AllScenarios
if ($Domain) { $scenarios = @($scenarios | Where-Object { $Domain -contains $_.domain }) }
if ($Scenario) { $scenarios = @($scenarios | Where-Object { $Scenario -contains $_.scenario }) }
if ($FromScenario) {
    $startOrder = ($AllScenarios | Where-Object { $_.scenario -eq $FromScenario } | Select-Object -First 1).order
    if ($null -ne $startOrder) {
        $scenarios = @($scenarios | Where-Object { $_.order -ge $startOrder })
    } else {
        Write-Warning "scenario '$FromScenario' not found in the set - -FromScenario ignored"
    }
}
if ($scenarios.Count -eq 0) {
    Write-Warning "No scenarios left after filtering."
    exit 0
}

$results = @()

foreach ($sc in $scenarios) {
    Write-Host ""
    Write-Host "=== [$($sc.order)] $($sc.domain)/$($sc.scenario) ===" -ForegroundColor Cyan
    if ($sc.expected.Count -gt 0) {
        Write-Host ("  Expected incident_type: " + ($sc.expected -join ", "))
    } else {
        Write-Host "  (fixture has no expected incident_type - observation only)"
    }
    $runLines = @($sc.lines | Where-Object { $_.kind -eq 'run' })
    $noteLines = @($sc.lines | Where-Object { $_.kind -eq 'note' })
    foreach ($l in $sc.lines) {
        $tag = if ($l.kind -eq 'run') { '[RUN]' } else { '[NOTE]' }
        $dtag = if ($l.destructive) { ' [DESTRUCTIVE]' } else { '' }
        $color = if ($l.kind -eq 'run') { 'White' } else { 'DarkYellow' }
        Write-Host "  $tag$dtag $($l.text)" -ForegroundColor $color
    }

    if ($sc.needs_second_host) {
        Write-Host "  -> needs a second host on the Host-Only network - this script cannot do that, skipping" -ForegroundColor Yellow
        $results += [pscustomobject]@{ Domain = $sc.domain; Scenario = $sc.scenario; Status = 'SKIP (second host)'; Missing = ''; Unexpected = '' }
        continue
    }
    if ($runLines.Count -eq 0) {
        Write-Host "  -> no automatically runnable lines - skipping (run by hand if you want)" -ForegroundColor Yellow
        $results += [pscustomobject]@{ Domain = $sc.domain; Scenario = $sc.scenario; Status = 'SKIP (manual only)'; Missing = ''; Unexpected = '' }
        continue
    }
    if ($sc.destructive -and -not $ConfirmDestructive) {
        Write-Host "  -> DESTRUCTIVE scenario (needs a VM snapshot) - pass -ConfirmDestructive, skipping" -ForegroundColor Red
        $results += [pscustomobject]@{ Domain = $sc.domain; Scenario = $sc.scenario; Status = 'SKIP (destructive)'; Missing = ''; Unexpected = '' }
        continue
    }
    if ($ListOnly) {
        $results += [pscustomobject]@{ Domain = $sc.domain; Scenario = $sc.scenario; Status = 'PLANNED'; Missing = ''; Unexpected = '' }
        continue
    }

    if ($noteLines.Count -gt 0) {
        Read-Host "  See [NOTE] lines above - handle them by hand if needed, then press Enter to continue"
    }
    if ($sc.destructive -or -not $Yes) {
        $ans = Read-Host "  Run this scenario's [RUN] lines? [Enter=yes, s=skip]"
        if ($ans -eq 's') {
            $results += [pscustomobject]@{ Domain = $sc.domain; Scenario = $sc.scenario; Status = 'SKIP (operator)'; Missing = ''; Unexpected = '' }
            continue
        }
    }

    $since = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss')
    foreach ($l in $runLines) {
        Write-Host "  > $($l.text)" -ForegroundColor DarkGray
        try {
            Invoke-Expression $l.text
        } catch {
            Write-Warning "    line failed: $_"
        }
    }

    $got = New-Object 'System.Collections.Generic.HashSet[string]'
    $expectedSet = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($t in $sc.expected) { [void]$expectedSet.Add($t) }
    $pollStart = Get-Date
    $deadline = $pollStart.AddSeconds($TimeoutSec)
    $encodedSource = [uri]::EscapeDataString($Source)
    Write-Host "  waiting up to ${TimeoutSec}s for incidents (polling every 5s)..." -ForegroundColor DarkGray
    do {
        try {
            # Filter on updated_at by hand instead of asking the API for time_from=: /incidents
            # compares created_at only, and an incident whose dedup bucket is still open is
            # UPDATED rather than re-created (bucket length = the correlation's timespan, up to
            # an hour). Re-running a scenario inside that bucket then produced a false MISSING
            # even though the detection had fired - seen live on exec_remote_access_tool and
            # th_exec_script_host_burst. Both sides are naive UTC ISO strings, so an ordinal
            # comparison is exact ("...T01:41:24.776710" > "...T01:41:20").
            $resp = Invoke-RestMethod "$SiemUrl/incidents?source_batch=$encodedSource&sort_by=updated_at&sort_dir=desc&limit=200" -TimeoutSec 20
            foreach ($inc in $resp.incidents) {
                if ([string]::CompareOrdinal([string]$inc.updated_at, $since) -ge 0) {
                    [void]$got.Add([string]$inc.incident_type)
                }
            }
        } catch {
            Write-Warning "    /incidents poll failed: $_"
        }
        $elapsed = [int]((Get-Date) - $pollStart).TotalSeconds
        Write-Host "  ... ${elapsed}s elapsed, got so far: [$($got -join ', ')]" -ForegroundColor DarkGray
        if ($expectedSet.Count -gt 0 -and $got.IsSupersetOf($expectedSet)) { break }
        if ((Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds 5
    } while ($true)

    $missing = @($sc.expected | Where-Object { -not $got.Contains($_) })
    $unexpected = @($got | Where-Object { $sc.expected -notcontains $_ })
    $status = if ($missing.Count -eq 0) { 'PASS' } else { 'MISSING' }
    $color = if ($status -eq 'PASS') { 'Green' } else { 'Red' }
    Write-Host ("  -> {0}  got: [{1}]" -f $status, ($got -join ', ')) -ForegroundColor $color
    if ($unexpected.Count -gt 0) {
        Write-Host ("     unexpected types (maybe overlap with another scenario): " + ($unexpected -join ', ')) -ForegroundColor Yellow
    }
    $results += [pscustomobject]@{ Domain = $sc.domain; Scenario = $sc.scenario; Status = $status; Missing = ($missing -join ','); Unexpected = ($unexpected -join ',') }
}

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
$results | Format-Table -AutoSize

$fails = @($results | Where-Object { $_.Status -eq 'MISSING' })
if ($fails.Count -gt 0) {
    Write-Host "$($fails.Count) scenarios with MISSING - see the table above and windows-vm-lab.md." -ForegroundColor Red
    exit 1
}
exit 0
