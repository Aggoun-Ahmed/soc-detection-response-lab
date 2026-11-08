# Copy rule XML into the official manager container and restart the manager service.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$single = Join-Path $root 'external/wazuh-docker/single-node'
if (-not (Test-Path $single)) { throw 'First run scripts/setup-wazuh.ps1' }
Push-Location $single
try {
  $container = (docker compose ps -q wazuh.manager).Trim()
  if (-not $container) { throw 'Manager container is not running.' }
  docker cp (Join-Path $root 'rules/soc_lab_rules.xml') "${container}:/var/ossec/etc/rules/soc_lab_rules.xml"
  if ($LASTEXITCODE -ne 0) { throw 'Failed to copy custom rules.' }
  docker compose restart wazuh.manager
  if ($LASTEXITCODE -ne 0) { throw 'Manager restart failed.' }
  Write-Host 'Rules installed. Verify using wazuh-logtest and manager logs before relying on the alerts.'
} finally { Pop-Location }
