# Installs Sysmon (from Sysinternals) with a pinned, hash-verified sysmon-modular
# config, or updates the config if Sysmon is already installed.
#
# The rules in Windows_Sysmon/ are matched against the RuleName values this
# config emits (see Windows_Sysmon/COVERAGE.md). When bumping the pin, update
# SYSMON_CONFIG_TAG in tools/reanchor_sysmon.py and re-run that script.
#
# Run as Administrator (e.g. via the Wazuh agent or a GPO startup script).

$sysinternals_repo = 'download.sysinternals.com'
$sysinternals_downloadlink = 'https://download.sysinternals.com/files/SysinternalsSuite.zip'
$sysinternals_folder = 'C:\Program Files\sysinternals'
$sysinternals_zip = 'SysinternalsSuite.zip'

# sysmon-modular "Balanced" profile for Sysmon 15.x, pinned to a release.
# Prebuilt configs are published as release assets (they are no longer in the repo).
$sysmonconfig_release = 'configs-082cba578667'
$sysmonconfig_downloadlink = "https://github.com/olafhartong/sysmon-modular/releases/download/$sysmonconfig_release/sysmonconfig.xml"
$sysmonconfig_sha256 = 'F115AAC5770DAE468E5CFB48C58A8B6E37588208A31F1B746812C534577A244B'
$sysmonconfig_file = 'sysmonconfig-export.xml'

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$OutPath = $env:TMP

$X = 0
do {
  Write-Output "Waiting for network"
  Start-Sleep -s 5
  $X += 1
} until(($connectresult = Test-NetConnection $sysinternals_repo -Port 443 | ? { $_.TcpTestSucceeded }) -or $X -eq 3)

if ($connectresult.TcpTestSucceeded -ne $true) {
  Write-Output "Unable to connect to Sysinternals Repo"
  exit 1
}

Try
{
  if (-not (Test-Path -Path "$sysinternals_folder\Sysmon64.exe")) {
    Write-Host 'Downloading Sysinternals Suite to C:\Program Files\sysinternals...'
    New-Item -Path $sysinternals_folder -ItemType Directory -Force | Out-Null
    Invoke-WebRequest -Uri $sysinternals_downloadlink -OutFile "$OutPath\$sysinternals_zip"
    Expand-Archive -Path "$OutPath\$sysinternals_zip" -DestinationPath $sysinternals_folder -Force
    Remove-Item -Path "$OutPath\$sysinternals_zip"
  }

  Write-Host "Downloading sysmon-modular config ($sysmonconfig_release)..."
  Invoke-WebRequest -Uri $sysmonconfig_downloadlink -OutFile "$OutPath\$sysmonconfig_file"
  $hash = (Get-FileHash -Algorithm SHA256 -Path "$OutPath\$sysmonconfig_file").Hash
  if ($hash -ne $sysmonconfig_sha256) {
    throw "sysmon config hash mismatch: expected $sysmonconfig_sha256, got $hash"
  }

  if (Get-Service 'Sysmon64' -ErrorAction SilentlyContinue) {
    Write-Host 'Sysmon is already installed - applying the pinned config'
    & "$sysinternals_folder\Sysmon64.exe" -c "$OutPath\$sysmonconfig_file"
  } else {
    Write-Host 'Installing Sysmon with the pinned config'
    & "$sysinternals_folder\Sysmon64.exe" -accepteula -i "$OutPath\$sysmonconfig_file"
  }
}
Catch
{
  Write-Error -Message "$($_.Exception.Message) $($_.Exception.ItemName)"
  exit 1
}
Finally
{
  Remove-Item -Path "$OutPath\$sysmonconfig_file" -ErrorAction SilentlyContinue
}
