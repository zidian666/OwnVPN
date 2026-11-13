param(
    [string]$SdkRoot = $env:ANDROID_HOME,
    [string]$NdkVersion = '30.0.16248370',
    [ValidateSet('arm64-v8a', 'x86_64')][string]$Abi = 'arm64-v8a',
    [switch]$RunOnDevice,
    [string]$DeviceSerial
)
$ErrorActionPreference = 'Stop'
if (-not $SdkRoot) { throw 'Set ANDROID_HOME or pass -SdkRoot.' }
$SdkRoot = (Resolve-Path -LiteralPath $SdkRoot).Path
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildDirectory = Join-Path $projectRoot "build-android-core-$Abi"
$cmake = Join-Path $SdkRoot 'cmake/3.31.6/bin/cmake.exe'
$ninja = Join-Path $SdkRoot 'cmake/3.31.6/bin/ninja.exe'
$toolchain = Join-Path $SdkRoot "ndk/$NdkVersion/build/cmake/android.toolchain.cmake"
foreach ($required in @($cmake, $ninja, $toolchain)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Missing Android tool: $required"
    }
}
& $cmake -S $projectRoot -B $buildDirectory -G Ninja `
    "-DCMAKE_MAKE_PROGRAM=$ninja" "-DCMAKE_TOOLCHAIN_FILE=$toolchain" `
    "-DANDROID_ABI=$Abi" '-DANDROID_PLATFORM=android-26' '-DANDROID_STL=c++_static' `
    '-DCMAKE_BUILD_TYPE=Debug' '-DOWNVPN_BUILD_WINDOWS_APP=OFF' '-DBUILD_TESTING=ON'
if ($LASTEXITCODE -ne 0) { throw 'Android core configuration failed.' }
& $cmake --build $buildDirectory --target portable_core_tests --parallel 4
if ($LASTEXITCODE -ne 0) { throw 'Android core compilation failed.' }
Write-Host "Built Android core tests ($Abi): $buildDirectory/portable_core_tests"
if (-not $RunOnDevice) {
    Write-Host 'Compilation passed. Device tests have not run; use -RunOnDevice to execute them.'
    return
}
$adb = Join-Path $SdkRoot 'platform-tools/adb.exe'
if (-not (Test-Path -LiteralPath $adb -PathType Leaf)) { throw 'Android platform-tools are missing.' }
$deviceArguments = @()
if ($DeviceSerial) { $deviceArguments = @('-s', $DeviceSerial) }
$state = & $adb @deviceArguments get-state
if ($LASTEXITCODE -ne 0 -or ($state -join '').Trim() -ne 'device') {
    throw 'Connect one authorized Android device, or select it with -DeviceSerial.'
}
$deviceApi = & $adb @deviceArguments shell getprop ro.build.version.sdk
if ($LASTEXITCODE -ne 0 -or ($deviceApi -join '').Trim() -notmatch '^\d+$' -or
    [int]($deviceApi -join '').Trim() -lt 26) {
    throw 'Device tests require Android API 26 or newer.'
}
$supportedAbis = & $adb @deviceArguments shell getprop ro.product.cpu.abilist
if ($LASTEXITCODE -ne 0 -or (($supportedAbis -join '').Trim() -split ',') -notcontains $Abi) {
    throw "Device does not support the selected ABI: $Abi"
}
$remoteBinary = '/data/local/tmp/ownvpn-core-test-' + [guid]::NewGuid().ToString('N')
try {
    & $adb @deviceArguments push (Join-Path $buildDirectory 'portable_core_tests') $remoteBinary
    if ($LASTEXITCODE -ne 0) { throw 'Failed to copy the test binary.' }
    & $adb @deviceArguments shell chmod 700 $remoteBinary
    if ($LASTEXITCODE -ne 0) { throw 'Failed to make the test binary executable.' }
    & $adb @deviceArguments shell "TMPDIR=/data/local/tmp $remoteBinary"
    if ($LASTEXITCODE -ne 0) { throw 'Android device core tests failed.' }
} finally {
    & $adb @deviceArguments shell rm -f $remoteBinary
    if ($LASTEXITCODE -ne 0) { Write-Warning "Test binary cleanup failed: $remoteBinary" }
}
