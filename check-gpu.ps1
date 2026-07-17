<#
    check-gpu.ps1 - after a reboot, confirm the NVIDIA GPU recovered and that Ollama is
    actually using it, with a tokens/sec benchmark so you can see the speedup.

      .\check-gpu.ps1              test the model from .env (default llama3.2:1b)
      .\check-gpu.ps1 -Model X     test a specific model tag

    Why this exists: a "GPU is lost" NVIDIA fault makes Ollama silently fall back to
    100% CPU, which makes a 7B model crawl. This script tells you, in one run, whether
    the GPU is healthy, whether Ollama is using it, and how fast generation actually is.

    It only needs Ollama - OpenWebUI and the tool bridge do not have to be running.
#>
[CmdletBinding()]
param(
    [string]$Model = ''
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot

# Reuse the project's .env so we test the model the assistant actually uses.
$EnvFile = Join-Path $Root '.env'
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        if ($_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') {
            Set-Item -Path "Env:$($Matches[1])" -Value $Matches[2]
        }
    }
}
if (-not $Model) {
    $Model = if ($env:MODEL) { $env:MODEL } else { 'llama3.2:1b' }
}

$OllamaExe = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'
$OllamaUrl = 'http://127.0.0.1:11434'

function Step($m) { Write-Host "==> " -ForegroundColor Blue -NoNewline; Write-Host $m }
function Ok($m)   { Write-Host "  " -NoNewline; Write-Host "OK " -ForegroundColor Green -NoNewline; Write-Host $m }
function Warn($m) { Write-Host "  " -NoNewline; Write-Host "!  " -ForegroundColor Yellow -NoNewline; Write-Host $m }
function Bad($m)  { Write-Host "  " -NoNewline; Write-Host "x  " -ForegroundColor Red -NoNewline; Write-Host $m }

function Test-Http($Url) {
    try { Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3 | Out-Null; return $true }
    catch { return $null -ne $_.Exception.Response }
}

# ---------------------------------------------------------------------------
# 1. Is the GPU visible to the driver at all?
# ---------------------------------------------------------------------------
Step "NVIDIA GPU health"

$gpuNames = @(Get-CimInstance Win32_VideoController -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name)
foreach ($g in $gpuNames) { Write-Host "  adapter: $g" }

# nvidia-smi is not always on PATH; check the usual install locations too.
$smi = $null
$cmd = Get-Command nvidia-smi -ErrorAction SilentlyContinue
if ($cmd) {
    $smi = $cmd.Source
} else {
    foreach ($p in @(
        "$env:SystemRoot\System32\nvidia-smi.exe",
        "$env:ProgramFiles\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    )) { if (Test-Path $p) { $smi = $p; break } }
}

$gpuHealthy = $false
if (-not $smi) {
    Warn "nvidia-smi not found - cannot query the GPU (NVIDIA driver may not be installed)"
} else {
    # 2>&1 on a native exe is avoided; let cmd swallow stderr and give us the text.
    $out = cmd /c "`"$smi`" --query-gpu=name,utilization.gpu,memory.used,memory.total --format=csv,noheader 2>&1"
    $text = ($out | Out-String).Trim()
    if ($text -match 'GPU is lost|No devices were found|Unable to determine') {
        Bad "GPU is NOT healthy - driver reports it as lost/absent:"
        Write-Host "     $text" -ForegroundColor Red
        Bad "Reboot to recover it. If it persists after a reboot, reinstall the NVIDIA driver."
    } elseif ($text) {
        Ok "GPU is healthy and visible to the driver:"
        Write-Host "     $text"
        $gpuHealthy = $true
    } else {
        Warn "nvidia-smi returned nothing useful"
    }
}

# ---------------------------------------------------------------------------
# 2. Make sure Ollama is up (this test does not need OpenWebUI).
# ---------------------------------------------------------------------------
Step "Ollama"
if (Test-Http "$OllamaUrl/api/tags") {
    Ok "already running"
} else {
    if (-not (Test-Path $OllamaExe)) { Bad "ollama.exe not found at $OllamaExe"; exit 1 }
    Start-Process -FilePath $OllamaExe -ArgumentList 'serve' -WindowStyle Hidden | Out-Null
    $waited = 0
    while ($waited -lt 30 -and -not (Test-Http "$OllamaUrl/api/tags")) { Start-Sleep -Seconds 1; $waited++ }
    if (Test-Http "$OllamaUrl/api/tags") { Ok "started" } else { Bad "ollama did not come up"; exit 1 }
}

# ---------------------------------------------------------------------------
# 3. Benchmark: one short generation, measured by Ollama's own counters.
# ---------------------------------------------------------------------------
Step "Benchmarking $Model (this also loads it into memory)"
Write-Host "  generating... (first run loads the model, so be patient)"

$body = @{
    model  = $Model
    prompt = 'In one short paragraph, explain what a default gateway is on a home network.'
    stream = $false
} | ConvertTo-Json -Depth 5

try {
    $r = Invoke-RestMethod -Uri "$OllamaUrl/api/generate" -Method Post `
        -ContentType 'application/json' -Body $body -TimeoutSec 600
} catch {
    Bad "generation failed: $($_.Exception.Message)"
    Bad "Is the model pulled? Try: ollama pull $Model"
    exit 1
}

# Ollama reports durations in nanoseconds.
$loadSec   = [math]::Round($r.load_duration / 1e9, 1)
$genTokens = [int]$r.eval_count
$genSec    = $r.eval_duration / 1e9
$promptTok = [int]$r.prompt_eval_count
$promptSec = $r.prompt_eval_duration / 1e9
$totalSec  = [math]::Round($r.total_duration / 1e9, 1)

$genRate    = if ($genSec    -gt 0) { [math]::Round($genTokens / $genSec, 1) }    else { 0 }
$promptRate = if ($promptSec -gt 0) { [math]::Round($promptTok / $promptSec, 1) } else { 0 }

Ok "model load:        $loadSec s"
Ok "prompt processing: $promptTok tokens at $promptRate tok/s"
Ok "generation:        $genTokens tokens at $genRate tok/s"
Ok "total:             $totalSec s"

# ---------------------------------------------------------------------------
# 4. Where did Ollama actually put the model?
# ---------------------------------------------------------------------------
Step "Model placement (ollama ps)"
$ps = cmd /c "`"$OllamaExe`" ps 2>&1"
$psText = ($ps | Out-String).Trim()
Write-Host $psText

$onGpu = $psText -match '\d+%\s*GPU'
$onCpu = $psText -match '100%\s*CPU'

# ---------------------------------------------------------------------------
# 5. Verdict
# ---------------------------------------------------------------------------
Write-Host ""
if ($onGpu) {
    Write-Host "VERDICT: GPU IS IN USE - $Model is running on the GPU at $genRate tok/s." -ForegroundColor Green
    Write-Host "For reference, this model on CPU-only ran at roughly 2-6 tok/s, so anything"
    Write-Host "in the tens of tok/s means the GPU recovered and is doing the work."
} elseif ($onCpu) {
    Write-Host "VERDICT: STILL ON CPU - $Model is running 100% on the CPU at $genRate tok/s." -ForegroundColor Yellow
    if (-not $gpuHealthy) {
        Write-Host "The GPU is still in a bad state (see above). Reboot to recover it; if that"
        Write-Host "does not work, reinstall the NVIDIA driver."
    } else {
        Write-Host "The GPU looks healthy but Ollama did not use it. The model may be too large"
        Write-Host "for available VRAM, or Ollama needs a restart to re-detect the GPU:"
        Write-Host "  .\openWebBuddy.ps1 stop-all   then   .\openWebBuddy.ps1"
    }
} else {
    Warn "Could not determine placement from 'ollama ps' (model may have unloaded already)."
    Write-Host "Generation ran at $genRate tok/s."
}
Write-Host ""
