param(
    [string]$BuildDir = "",
    [string]$ArtifactDir = ""
)

$ErrorActionPreference = "Stop"

function Assert-LastExitCode {
    param(
        [string]$Action
    )

    if ($LASTEXITCODE -ne 0) {
        throw "$Action failed with exit code $LASTEXITCODE."
    }
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\\..")).Path
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $RepoRoot "build\\release-windows"
}
if ([string]::IsNullOrWhiteSpace($ArtifactDir)) {
    $ArtifactDir = Join-Path $RepoRoot "artifacts\\windows"
}

python (Join-Path $RepoRoot "scripts\\release\\generate_icons.py") `
    (Join-Path $RepoRoot "apps\\desktop_qt\\resources\\zara-re-platform.png") `
    (Join-Path $RepoRoot "apps\\desktop_qt\\resources")
Assert-LastExitCode "Icon generation"

$CmakeArgs = @(
    "-S", $RepoRoot,
    "-B", $BuildDir,
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DBUILD_TESTING=OFF",
    "-DZARA_BUILD_CLI=ON",
    "-DZARA_BUILD_DESKTOP_QT=ON",
    "-DVCPKG_MANIFEST_MODE=OFF"
)

if (-not [string]::IsNullOrWhiteSpace($env:CMAKE_PREFIX_PATH)) {
    $CmakeArgs += "-DCMAKE_PREFIX_PATH=$($env:CMAKE_PREFIX_PATH)"
}

if (-not [string]::IsNullOrWhiteSpace($env:CMAKE_TOOLCHAIN_FILE)) {
    $CmakeArgs += "-DCMAKE_TOOLCHAIN_FILE=$($env:CMAKE_TOOLCHAIN_FILE)"
}

cmake @CmakeArgs
Assert-LastExitCode "CMake configure"

cmake --build $BuildDir --config Release
Assert-LastExitCode "CMake build"
if (Test-Path $ArtifactDir) {
    Remove-Item -Recurse -Force $ArtifactDir
}
New-Item -ItemType Directory -Force -Path $ArtifactDir | Out-Null

cpack --config (Join-Path $BuildDir "CPackConfig.cmake") -G NSIS -B $ArtifactDir
Assert-LastExitCode "CPack packaging"
