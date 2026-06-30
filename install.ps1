<#
.SYNOPSIS
  gitlawb installer for Windows - downloads pre-built binaries from GitHub Releases.
.EXAMPLE
  irm https://gitlawb.com/install.ps1 | iex
.EXAMPLE
  & ([scriptblock]::Create((irm https://gitlawb.com/install.ps1))) -Version v0.3.9
#>
[CmdletBinding()]
param(
  [string]$Version = "latest"
)

$ErrorActionPreference = "Stop"

# Windows PowerShell 5.1 may default to TLS 1.0; GitHub requires TLS 1.2+.
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$Repo = if ($env:GITLAWB_RELEASE_REPO) { $env:GITLAWB_RELEASE_REPO } else { "Gitlawb/node" }
$InstallDir = if ($env:GITLAWB_INSTALL_DIR) { $env:GITLAWB_INSTALL_DIR } else { "$env:LOCALAPPDATA\Programs\gitlawb" }

$arch = if ($env:PROCESSOR_ARCHITEW6432) {
  $env:PROCESSOR_ARCHITEW6432
} else {
  $env:PROCESSOR_ARCHITECTURE
}
if ($arch -ne "AMD64") {
  throw "Unsupported architecture: $arch. Only x64 Windows binaries are published. Use WSL for arm64."
}
$target = "x86_64-pc-windows-msvc"

if ($Version -eq "latest") {
  Write-Host "Fetching latest release version..."
  $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing -Headers @{ "User-Agent" = "gitlawb-installer" }
  $tag = $rel.tag_name
} elseif ($Version.StartsWith("v")) {
  $tag = $Version
} else {
  $tag = "v$Version"
}
$ver = $tag.TrimStart("v")

$archive = "gitlawb-node-$ver-$target.zip"
$url = "https://github.com/$Repo/releases/download/$tag/$archive"

Write-Host "Installing gitlawb $tag for windows/x64"
Write-Host "  Archive: $archive"
Write-Host "  Into:    $InstallDir"

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("gitlawb-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $zipPath = Join-Path $tmp $archive
  Write-Host "Downloading..."
  Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing -Headers @{ "User-Agent" = "gitlawb-installer" }

  # Verify checksum. Every published asset has a matching .sha256, so fail closed
  # if it cannot be fetched rather than installing an unverified binary.
  $sumPath = "$zipPath.sha256"
  Invoke-WebRequest -Uri "$url.sha256" -OutFile $sumPath -UseBasicParsing -Headers @{ "User-Agent" = "gitlawb-installer" }
  $expected = ((Get-Content $sumPath -Raw).Trim() -split '\s+')[0].ToLower()
  $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
  if ($expected -ne $actual) {
    throw "checksum mismatch! expected $expected got $actual"
  }
  Write-Host "  checksum OK"

  Write-Host "Extracting..."
  $extract = Join-Path $tmp "extract"
  Expand-Archive -Path $zipPath -DestinationPath $extract -Force
  $pkgDir = Get-ChildItem -Path $extract -Directory | Select-Object -First 1

  New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
  # The Windows archive always ships the two CLI binaries; the daemon is optional.
  $requiredBins = @("gl.exe", "git-remote-gitlawb.exe")
  $optionalBins = @("gitlawb-node.exe")
  $missing = $requiredBins | Where-Object {
    -not (Test-Path (Join-Path $pkgDir.FullName $_))
  }
  if ($missing.Count -gt 0) {
    throw "archive is missing required binaries: $($missing -join ', ')"
  }

  $installed = @()
  foreach ($bin in $requiredBins + $optionalBins) {
    $src = Join-Path $pkgDir.FullName $bin
    if (Test-Path $src) {
      Copy-Item -Path $src -Destination (Join-Path $InstallDir $bin) -Force
      $installed += $bin
    }
  }

  # Drop binaries no longer shipped (e.g. an optional one removed in a new release)
  # so an upgrade in place never leaves a stale, mixed-version install behind.
  foreach ($bin in $requiredBins + $optionalBins) {
    if ($installed -notcontains $bin) {
      $dst = Join-Path $InstallDir $bin
      if (Test-Path $dst) { Remove-Item -Path $dst -Force }
    }
  }

  Write-Host ""
  Write-Host "Installed gitlawb $tag"
  foreach ($bin in $installed) { Write-Host "  $bin -> $InstallDir\$bin" }
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

# Add to the user PATH if missing.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ';') -notcontains $InstallDir) {
  $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
  [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
  Write-Host ""
  Write-Host "Added $InstallDir to your PATH. Restart your terminal, then run:"
} else {
  Write-Host ""
  Write-Host "Run:"
}
Write-Host "  gl doctor"
Write-Host "  gl quickstart"
Write-Host ""
Write-Host "Docs: https://docs.gitlawb.com"
