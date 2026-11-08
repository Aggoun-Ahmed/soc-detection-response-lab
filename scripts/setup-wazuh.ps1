# Bootstraps Wazuh's OFFICIAL pinned Docker distribution on Windows PowerShell.
# Inspect before executing. Requires Docker Desktop, Git, Python (separately).
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$external = Join-Path $projectRoot 'external'
$vendor = Join-Path $external 'wazuh-docker'
$version = 'v4.14.10'  # Pinned to a documented v4 release; check upstream for security fixes.

foreach ($cmd in @('git','docker')) {
  if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "$cmd missing. Install it first." }
}
docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker engine is not running. Start Docker Desktop.' }
New-Item -ItemType Directory -Path $external -Force | Out-Null
if (-not (Test-Path $vendor)) {
  git clone --depth 1 --branch $version https://github.com/wazuh/wazuh-docker.git $vendor
  if ($LASTEXITCODE -ne 0) { throw 'Wazuh Git clone failed.' }
}
$single = Join-Path $vendor 'single-node'
$config = Join-Path $single 'config/wazuh_cluster/wazuh_manager.conf'
if (-not (Test-Path $config)) { throw "Expected Wazuh manager configuration not found: $config" }
$content = Get-Content -Path $config -Raw
$labBlock = @'
  <!-- BEGIN SOC_PORTFOLIO_LOGCOLLECTOR -->
  <localfile>
    <log_format>json</log_format>
    <location>/var/ossec/logs/lab-events.jsonl</location>
  </localfile>
  <!-- END SOC_PORTFOLIO_LOGCOLLECTOR -->
'@
if ($content -notmatch 'BEGIN SOC_PORTFOLIO_LOGCOLLECTOR') {
  $loc = $content.LastIndexOf('</ossec_config>')
  if ($loc -lt 0) { throw 'No closing </ossec_config> found; upstream Wazuh config may have changed.' }
  $content = $content.Insert($loc, $labBlock + "`n")
  Set-Content -Path $config -Value $content -Encoding UTF8
}
Push-Location $single
try {
  Write-Host 'Generating official self-signed indexer certificates...'
  docker compose -f generate-indexer-certs.yml run --rm generator
  if ($LASTEXITCODE -ne 0) { throw 'Certificate generation failed.' }
  Write-Host 'Starting Wazuh single-node stack...'
  docker compose up -d
  if ($LASTEXITCODE -ne 0) { throw 'Docker Compose failed.' }
  Write-Host 'Started stack. Install rules with .\scripts\install-rules.ps1 after manager becomes healthy.'
  Write-Host 'Dashboard: https://localhost (HTTPS self-signed certificate).'
} finally { Pop-Location }
