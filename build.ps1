param([switch]$SkipTests)
$ErrorActionPreference = 'Stop'
$toolchain = 'D:\DevTools\winlibs-gcc-16.2.0\mingw64\bin'
if (Test-Path -LiteralPath $toolchain) { $env:Path = $toolchain + ';' + $env:Path }
$projectRoot = $PSScriptRoot
$projectConfiguration = Get-Content -LiteralPath "$projectRoot\CMakeLists.txt" -Raw
$versionMatch = [regex]::Match($projectConfiguration, 'project\(\s*OwnVPN\s+VERSION\s+(\d+\.\d+\.\d+)\b')
if (-not $versionMatch.Success) { throw 'Cannot determine release version from CMakeLists.txt' }
$releaseVersion = $versionMatch.Groups[1].Value
$releaseFileName = "OwnVPN-$releaseVersion.exe"
& cmake -S $projectRoot -B "$projectRoot\build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
if ($LASTEXITCODE -ne 0) { throw 'CMake configuration failed' }
& cmake --build "$projectRoot\build"
if ($LASTEXITCODE -ne 0) { throw 'Build failed' }
if (-not $SkipTests) {
    & ctest --test-dir "$projectRoot\build" --output-on-failure
    if ($LASTEXITCODE -ne 0) { throw 'Tests failed' }
}
New-Item -ItemType Directory -Path "$projectRoot\dist" -Force | Out-Null
Copy-Item -LiteralPath "$projectRoot\build\OwnVPN.exe" -Destination "$projectRoot\dist\$releaseFileName" -Force
Copy-Item -LiteralPath "$projectRoot\README.md" -Destination "$projectRoot\dist\README.md" -Force
Copy-Item -LiteralPath "$projectRoot\THIRD_PARTY_NOTICES.txt" -Destination "$projectRoot\dist\THIRD_PARTY_NOTICES.txt" -Force
Copy-Item -LiteralPath "$projectRoot\build\_deps\zxing-cpp-3.1.1\LICENSE" -Destination "$projectRoot\dist\LICENSE-ZXing.txt" -Force
Copy-Item -LiteralPath "$projectRoot\build\downloads\zxing-cpp-3.1.1.tar.gz" -Destination "$projectRoot\dist\ZXing-Cpp-3.1.1-source.tar.gz" -Force
Write-Host "Built: $projectRoot\dist\$releaseFileName"
