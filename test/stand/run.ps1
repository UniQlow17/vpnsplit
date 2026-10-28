<#
.SYNOPSIS
Runs the Linux network stand (test/stand) in a privileged Docker container.

.DESCRIPTION
Builds the Linux vpnsplit binary on the host, builds the stand image once
(alpine + iproute2, wireguard-tools, dnsmasq, ...), then runs stand.sh in a
`docker run --rm --privileged` container. Everything that changes the network
happens inside the container, never on this machine.

.PARAMETER HomeVariant
How the home VPN client routes: a (0/1 + 128/1 in the main table, default),
b (wg-quick style policy routing), c (own routing table via ip rule).
Only a is supported by vpnsplit now; b and c only set up the topology.

.PARAMETER Only
Run only the scenarios whose name contains this text (S1, S3, S6, ...).

.PARAMETER Rebuild
Rebuild the stand image.
#>
[CmdletBinding()]
param(
    [ValidateSet('a', 'b', 'c')][string]$HomeVariant = 'a',
    [string]$Only = '',
    [switch]$Rebuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$build = Join-Path $PSScriptRoot '.build'
New-Item -ItemType Directory -Force $build | Out-Null

foreach ($tool in 'go', 'docker') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        Write-Host "'$tool' was not found in PATH" -ForegroundColor Red
        exit 1
    }
}

Write-Host '== building the linux binary' -ForegroundColor Cyan
Push-Location $repo
try {
    $saved = @{ GOOS = $env:GOOS; GOARCH = $env:GOARCH; CGO_ENABLED = $env:CGO_ENABLED }
    $env:GOOS = 'linux'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    go build -o (Join-Path $build 'vpnsplit') ./cmd/vpnsplit
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
finally {
    foreach ($k in $saved.Keys) {
        if ($null -eq $saved[$k]) { Remove-Item "Env:$k" -ErrorAction SilentlyContinue } else { Set-Item "Env:$k" $saved[$k] }
    }
    Pop-Location
}

$image = 'vpnsplit-stand'
$have = docker images -q $image
if ($Rebuild -or -not $have) {
    Write-Host '== building the stand image' -ForegroundColor Cyan
    docker build -t $image $PSScriptRoot
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host '== running the stand' -ForegroundColor Cyan
docker run --rm --privileged `
    -e "HOME_VARIANT=$HomeVariant" -e "ONLY=$Only" `
    -v "${PSScriptRoot}:/stand" `
    $image bash /stand/stand.sh
exit $LASTEXITCODE
