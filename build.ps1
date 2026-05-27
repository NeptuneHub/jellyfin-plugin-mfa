# Build and package the Jellyfin Two-Factor Authentication plugin.
param(
    [string]$Configuration = "Release",
    [switch]$Install
)

$ProjectDir = "$PSScriptRoot\src\Jellyfin.Plugin.TwoFactorAuth"
$OutputDir = "$PSScriptRoot\dist\TwoFactorAuth"

if (Test-Path $OutputDir) { Remove-Item -Recurse -Force $OutputDir }
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Building plugin ($Configuration)..." -ForegroundColor Cyan
dotnet publish $ProjectDir -c $Configuration -o "$PSScriptRoot\dist\publish" --nologo
if ($LASTEXITCODE -ne 0) { exit 1 }

# The plugin has no native dependencies — just the managed plugin + its two NuGet deps.
$RequiredFiles = @(
    "Jellyfin.Plugin.TwoFactorAuth.dll",
    "Otp.NET.dll",
    "QRCoder.dll"
)

foreach ($file in $RequiredFiles) {
    $src = "$PSScriptRoot\dist\publish\$file"
    if (Test-Path $src) {
        Copy-Item $src $OutputDir
    }
}

Copy-Item "$ProjectDir\meta.json" $OutputDir

Write-Host "`nPlugin built to: $OutputDir" -ForegroundColor Green
Get-ChildItem $OutputDir | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

if ($Install) {
    $JellyfinPlugins = "$env:LOCALAPPDATA\jellyfin\plugins\TwoFactorAuth"
    if (Test-Path $JellyfinPlugins) { Remove-Item -Recurse -Force $JellyfinPlugins }
    Copy-Item -Recurse $OutputDir $JellyfinPlugins
    Write-Host "`nInstalled to: $JellyfinPlugins" -ForegroundColor Green
    Write-Host "Restart Jellyfin to load the plugin." -ForegroundColor Yellow
}
