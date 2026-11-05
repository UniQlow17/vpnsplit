<#
.SYNOPSIS
Build helper for vpnsplit on Windows (replacement for make).

.DESCRIPTION
Runs the same targets as the Makefile (build, test, vet, fmt, clean) without
requiring make, except snapshot (it needs goreleaser: run
"goreleaser release --snapshot --clean" directly). Works from any current directory: the script always runs in
the repository root. Compatible with Windows PowerShell 5.1 and PowerShell 7.

.PARAMETER Target
Task to run: build (default), test, vet, fmt, clean.

.PARAMETER Version
Version string embedded into the binary (-X main.version). Default: dev.

.EXAMPLE
.\build.ps1
Builds vpnsplit.exe in the repository root.

.EXAMPLE
.\build.ps1 build -Version 1.2.0
Builds vpnsplit.exe with version 1.2.0.

.EXAMPLE
.\build.ps1 test

.EXAMPLE
.\build.ps1 clean
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('build', 'test', 'vet', 'fmt', 'clean')]
    [string]$Target = 'build',

    [string]$Version = 'dev'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Version -notmatch '^[A-Za-z0-9._+\-]+$') {
    Write-Host "Invalid -Version '$Version': allowed characters A-Z a-z 0-9 . _ + -" -ForegroundColor Red
    exit 1
}

function Assert-Tool {
    param([string]$Name)
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Write-Host "'$Name' was not found in PATH. Install Go from https://go.dev/dl/ and restart the terminal." -ForegroundColor Red
        exit 1
    }
}

function Assert-ExitCode {
    param([string]$What)
    if ($LASTEXITCODE -ne 0) {
        Write-Host "$What failed (exit code $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
}

Push-Location $PSScriptRoot
try {
    switch ($Target) {
        'build' {
            Assert-Tool 'go'
            $goexe = & go env GOEXE
            Assert-ExitCode 'go env'
            $goexe = "$goexe".Trim()
            $out = "vpnsplit$goexe"
            Write-Host "Building $out (version $Version)..."
            $prevCgo = $env:CGO_ENABLED
            try {
                $env:CGO_ENABLED = '0'
                & go build -trimpath -ldflags "-s -w -X main.version=$Version" -o $out ./cmd/vpnsplit
                Assert-ExitCode 'go build'
            }
            finally {
                if ($null -eq $prevCgo) {
                    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
                }
                else {
                    $env:CGO_ENABLED = $prevCgo
                }
            }
            Write-Host "OK: $(Join-Path $PSScriptRoot $out)"
        }
        'test' {
            Assert-Tool 'go'
            Write-Host 'Running go test ./...'
            & go test ./...
            Assert-ExitCode 'go test'
        }
        'vet' {
            Assert-Tool 'go'
            Write-Host 'Running go vet ./...'
            & go vet ./...
            Assert-ExitCode 'go vet'
        }
        'fmt' {
            Assert-Tool 'gofmt'
            Write-Host 'Running gofmt -w .'
            & gofmt -w .
            Assert-ExitCode 'gofmt'
        }
        'clean' {
            Write-Host 'Cleaning build artifacts...'
            foreach ($p in 'vpnsplit', 'vpnsplit.exe', 'dist') {
                if (Test-Path -LiteralPath $p) {
                    try {
                        Remove-Item -LiteralPath $p -Recurse -Force
                    }
                    catch {
                        Write-Host "Cannot remove '$p': $($_.Exception.Message) (is vpnsplit running?)" -ForegroundColor Red
                        exit 1
                    }
                    Write-Host "Removed $p"
                }
            }
        }
    }
}
finally {
    Pop-Location
}
