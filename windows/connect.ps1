# Requires Windows OpenSSH Client and an already connected EasyTier network.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [System.Net.IPAddress]$Target,
    [ValidatePattern('^[a-z][a-z0-9_-]{0,30}$')]
    [string]$User = 'colabssh',
    [ValidateRange(1024, 65535)]
    [int]$Port = 2222,
    [string]$IdentityFile,
    [string[]]$Forward = @(),
    [switch]$Shell
)
$ErrorActionPreference = 'Stop'
if (-not (Get-Command ssh.exe -ErrorAction SilentlyContinue)) {
    throw 'Windows OpenSSH Client is required.'
}
if ($Target.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Use the Colab EasyTier virtual IPv4 address.'
}
$knownDir = Join-Path $env:LOCALAPPDATA 'colab-easytier-ssh'
New-Item -ItemType Directory -Force -Path $knownDir | Out-Null
$knownFile = Join-Path $knownDir 'known_hosts'
$sshArgs = @('-p', "$Port", '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3', '-o', "UserKnownHostsFile=$knownFile")
if ($IdentityFile) {
    $identity = (Resolve-Path -LiteralPath $IdentityFile).Path
    $sshArgs += @('-i', $identity, '-o', 'IdentitiesOnly=yes')
}
foreach ($mapping in $Forward) {
    if ($mapping -notmatch '^(\d{1,5}):(\d{1,5})$') {
        throw 'Each -Forward value must be LOCAL_PORT:REMOTE_PORT, e.g. 8000:8000.'
    }
    $localPort = [int]$Matches[1]
    $remotePort = [int]$Matches[2]
    if ($localPort -lt 1024 -or $localPort -gt 65535 -or $remotePort -lt 1 -or $remotePort -gt 65535) {
        throw 'Local ports must be 1024-65535; remote ports must be 1-65535.'
    }
    $sshArgs += @('-L', "127.0.0.1:${localPort}:127.0.0.1:${remotePort}")
}
if ($Forward.Count -gt 0 -and -not $Shell) { $sshArgs += '-N' }
$sshArgs += "${User}@${Target}"
Write-Host 'On first connection, compare the SSH fingerprint with the one shown in Colab.'
& ssh.exe @sshArgs
exit $LASTEXITCODE
