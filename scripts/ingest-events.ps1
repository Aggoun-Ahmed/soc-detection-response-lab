# Stream a generated JSONL file into the manager log file monitored by Wazuh.
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$single = Join-Path $root 'external/wazuh-docker/single-node'
$source = Join-Path $root 'samples/generated-events.jsonl'
if (-not (Test-Path $source)) { throw 'Run scripts/generate_events.py first.' }
if (-not (Test-Path $single)) { throw 'Run scripts/setup-wazuh.ps1 first.' }
Push-Location $single
try {
  # Use stdin redirection through cmd to preserve ASCII-only generated JSONL line boundaries.
  $cmd = 'docker compose exec -T wazuh.manager sh -c "cat >> /var/ossec/logs/lab-events.jsonl"'
  $process = Start-Process -FilePath 'cmd.exe' -ArgumentList '/d', '/s', '/c', "type `"$source`" | $cmd" -Wait -NoNewWindow -PassThru
  if ($process.ExitCode -ne 0) { throw 'Failed to stream log data into the Wazuh manager.' }
  Write-Host 'Synthetic events appended. Refresh dashboard and confirm alerts; ingestion is not proof of detection.'
} finally { Pop-Location }
