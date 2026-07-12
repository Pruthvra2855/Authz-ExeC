# Builds Authz-ExeC into dist\Authz-ExeC.jar
# Usage:  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

# --- locate burpsuite.jar (Pro or Community) ---
$burpCandidates = @(
  "$env:LOCALAPPDATA\Programs\BurpSuitePro\burpsuite.jar",
  "$env:LOCALAPPDATA\Programs\BurpSuiteCommunity\burpsuite_community.jar",
  "$env:ProgramFiles\BurpSuitePro\burpsuite.jar",
  "$env:ProgramFiles\BurpSuiteCommunity\burpsuite_community.jar"
)
$burp = $burpCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $burp) { throw "burpsuite.jar not found. Edit build.ps1 and set `$burp manually." }
Write-Host "Burp jar : $burp"

# --- locate a javac >= 17 (its bin also has jar.exe) ---
function Find-Javac {
  $cands = New-Object System.Collections.Generic.List[string]
  Get-ChildItem "$env:ProgramFiles\Java" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
    $p = Join-Path $_.FullName "bin\javac.exe"; if (Test-Path $p) { $cands.Add($p) }
  }
  $cmd = Get-Command javac -ErrorAction SilentlyContinue
  if ($cmd) { $cands.Add($cmd.Source) }
  foreach ($c in $cands) {
    $v = & $c -version 2>&1
    if ($v -match "javac (\d+)") { if ([int]$Matches[1] -ge 17) { return $c } }
  }
  return $null
}
$javac = Find-Javac
if (-not $javac) { throw "No JDK 17+ javac found. Install a JDK 17+ or edit build.ps1." }
$bin = Split-Path -Parent $javac
$jar = Join-Path $bin "jar.exe"
Write-Host "javac    : $javac"

# --- compile + package ---
if (Test-Path out)  { Remove-Item out  -Recurse -Force }
if (Test-Path dist) { Remove-Item dist -Recurse -Force }
New-Item -ItemType Directory out, dist | Out-Null

$sources = Get-ChildItem -Recurse src -Filter *.java | ForEach-Object { $_.FullName }
& $javac -implicit:none -cp $burp -d out $sources
if ($LASTEXITCODE -ne 0) { throw "compile failed" }

& $jar --create --file dist\Authz-ExeC.jar -C out authzmatrix
if ($LASTEXITCODE -ne 0) { throw "jar failed" }

Write-Host ""
Write-Host "Built: $root\dist\Authz-ExeC.jar" -ForegroundColor Green
Write-Host "Load in Burp: Extensions -> Installed -> Add -> Extension type: Java -> select the jar."
