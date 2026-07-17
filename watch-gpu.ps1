<#
    watch-gpu.ps1 - live view of what the GPU and Ollama are doing.

      .\watch-gpu.ps1              refresh every 1s until you press Ctrl+C
      .\watch-gpu.ps1 -Interval 2  refresh every 2s

    Run this in one window while you chat in the browser. When the model loads you will
    see VRAM jump by several GB; while it is answering, GPU utilization should climb into
    the high tens/nineties. If VRAM stays flat and 'PROCESSOR' says CPU, the GPU is not
    being used.
#>
[CmdletBinding()]
param(
    [int]$Interval = 1
)

$ErrorActionPreference = 'Continue'
$OllamaExe = Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'

# nvidia-smi is not always on PATH.
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
if (-not $smi) { Write-Host "nvidia-smi not found - is the NVIDIA driver installed?" -ForegroundColor Red; exit 1 }

function Bar([int]$pct, [int]$width = 30) {
    if ($pct -lt 0) { $pct = 0 }; if ($pct -gt 100) { $pct = 100 }
    $filled = [math]::Round($width * $pct / 100)
    return ('#' * $filled) + ('.' * ($width - $filled))
}

Write-Host "Watching GPU + Ollama. Press Ctrl+C to stop." -ForegroundColor Cyan
Write-Host ""

while ($true) {
    $line = (cmd /c "`"$smi`" --query-gpu=utilization.gpu,memory.used,memory.total,temperature.gpu --format=csv,noheader,nounits 2>&1" | Out-String).Trim()
    $parts = $line -split '\s*,\s*'

    $stamp = Get-Date -Format 'HH:mm:ss'
    if ($parts.Count -ge 4 -and $parts[0] -match '^\d+$') {
        $util   = [int]$parts[0]
        $usedMB = [int]$parts[1]
        $totMB  = [int]$parts[2]
        $temp   = [int]$parts[3]
        $vramPct = if ($totMB -gt 0) { [math]::Round(100 * $usedMB / $totMB) } else { 0 }

        $utilColor = if ($util -ge 50) { 'Green' } elseif ($util -ge 10) { 'Yellow' } else { 'DarkGray' }

        Write-Host "[$stamp] GPU " -NoNewline
        Write-Host ("{0,3}% " -f $util) -ForegroundColor $utilColor -NoNewline
        Write-Host "[$(Bar $util)]  " -ForegroundColor $utilColor -NoNewline
        Write-Host ("VRAM {0,5} / {1} MiB ({2}%)  {3}C" -f $usedMB, $totMB, $vramPct, $temp)
    } else {
        Write-Host "[$stamp] GPU query failed: $line" -ForegroundColor Red
    }

    # What Ollama currently has loaded, and on what processor.
    $ps = (cmd /c "`"$OllamaExe`" ps 2>&1" | Out-String)
    $modelLine = ($ps -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -Skip 1 | Select-Object -First 1)
    if ($modelLine) {
        $m = ($modelLine -replace '\s{2,}', ' | ').Trim()
        $color = if ($modelLine -match 'GPU') { 'Green' } else { 'Yellow' }
        Write-Host "           ollama: $m" -ForegroundColor $color
    } else {
        Write-Host "           ollama: no model loaded (idle)" -ForegroundColor DarkGray
    }

    Start-Sleep -Seconds $Interval
}
