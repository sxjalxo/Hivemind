<#
.SYNOPSIS
Keep the IAP tunnels to the GCP honeypot VM up (admin SSH and the evaluation Cowrie).

  .\infra\wild-vm\iap-tunnels.ps1            # start any tunnel that is not listening; show status
  .\infra\wild-vm\iap-tunnels.ps1 -Stop      # end them
  .\infra\wild-vm\iap-tunnels.ps1 -Register  # run it at every logon (a per-user scheduled task)

Reads GCP_PROJECT, GCP_ZONE and GCP_INSTANCE from the repo-root .env. Everything that
talks to the VM goes through these listeners, so a changing home IP never matters:
  127.0.0.1:22022 -> VM 50022  admin SSH: wild-pull (as host.docker.internal), deploy, eval gate
  127.0.0.2:2222  -> VM 2222   evaluation Cowrie SSH (127.0.0.1:2222 is the local cowrie-01)
  127.0.0.2:2223  -> VM 2223   evaluation Cowrie telnet
gcloud's own connection self-test hangs on Windows, hence --iap-tunnel-disable-connection-check.
#>
param([switch]$Stop, [switch]$Register)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$tunnels = @(
    @{ Local = '127.0.0.1'; LocalPort = 22022; Remote = 50022 },
    @{ Local = '127.0.0.2'; LocalPort = 2222;  Remote = 2222 },
    @{ Local = '127.0.0.2'; LocalPort = 2223;  Remote = 2223 }
)

function Get-TunnelProcesses {
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
        Where-Object { $_.CommandLine -match 'start-iap-tunnel' }
}

$envFile = Join-Path $root '.env'
$cfg = @{}
if (Test-Path $envFile) {
    Get-Content $envFile | Where-Object { $_ -match '^(GCP_PROJECT|GCP_ZONE|GCP_INSTANCE)=' } | ForEach-Object {
        $k, $v = $_ -split '=', 2
        $cfg[$k] = $v.Trim().Trim('"').Trim("'")
    }
}

if ($Stop) {
    # Only this VM's tunnels; without GCP_INSTANCE in .env, every start-iap-tunnel process.
    $found = @(Get-TunnelProcesses)
    if ($cfg.GCP_INSTANCE) {
        $found = @($found | Where-Object { $_.CommandLine -match [regex]::Escape($cfg.GCP_INSTANCE) })
    } else {
        Write-Output 'GCP_INSTANCE is not set in .env: stopping every start-iap-tunnel process'
    }
    $found | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
    Write-Output "tunnels stopped: $($found.Count)"
    return
}

if ($Register) {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    # The defaults refuse to start on battery and stop the task when going onto it (a laptop).
    # Whether the gcloud children outlive this task's job object is checked with
    # Start-ScheduledTask in the cut-over, not assumed.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskName 'Hivemind IAP tunnels' -Action $action -Trigger $trigger `
        -Settings $settings -Force | Out-Null
    Write-Output "registered: 'Hivemind IAP tunnels' runs at your logon"
    return
}

foreach ($name in 'GCP_PROJECT', 'GCP_ZONE', 'GCP_INSTANCE') {
    if (-not $cfg[$name]) { throw "$name is not set in $envFile" }
}

$gcloud = Join-Path $env:LOCALAPPDATA 'Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
if (-not (Test-Path $gcloud)) { $gcloud = (Get-Command gcloud.cmd -ErrorAction Stop).Source }

# At logon the network is often not up yet and a tunnel's gcloud exits at once, so a
# tunnel still missing after 30 s is started again, up to five times (~3 minutes).
for ($attempt = 1; $attempt -le 5; $attempt++) {
    $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
    foreach ($t in $tunnels) {
        $up = $listening | Where-Object { $_.LocalAddress -eq $t.Local -and $_.LocalPort -eq $t.LocalPort }
        if (-not $up) {
            Start-Process -WindowStyle Hidden -FilePath $gcloud -ArgumentList @(
                'compute', 'start-iap-tunnel', $cfg.GCP_INSTANCE, $t.Remote,
                "--local-host-port=$($t.Local):$($t.LocalPort)",
                "--zone=$($cfg.GCP_ZONE)", "--project=$($cfg.GCP_PROJECT)",
                '--iap-tunnel-disable-connection-check')
        }
    }

    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Seconds 2
        $listening = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
        $missing = @($tunnels | Where-Object {
            $t = $_; -not ($listening | Where-Object { $_.LocalAddress -eq $t.Local -and $_.LocalPort -eq $t.LocalPort })
        })
    } while ($missing.Count -and (Get-Date) -lt $deadline)
    if (-not $missing.Count) { break }
}

foreach ($t in $tunnels) {
    $state = if ($missing | Where-Object { $_.LocalPort -eq $t.LocalPort -and $_.Local -eq $t.Local }) { 'DOWN' } else { 'up' }
    Write-Output ("{0,-4} {1}:{2} -> VM {3}" -f $state, $t.Local, $t.LocalPort, $t.Remote)
}
if ($missing.Count) { exit 1 }
