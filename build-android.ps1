param([switch]$Install, [switch]$Test, [string]$DeviceSerial)
$ErrorActionPreference='Stop'
foreach($name in @('JAVA_HOME','ANDROID_HOME','GRADLE_USER_HOME')) {
    if(-not [Environment]::GetEnvironmentVariable($name,'Process')) {
        [Environment]::SetEnvironmentVariable($name,[Environment]::GetEnvironmentVariable($name,'User'),'Process')
    }
}
$gradle='D:/DevTools/Gradle/gradle-8.13/bin/gradle.bat'
if(!(Test-Path -LiteralPath $gradle)) { $gradle=(Get-Command gradle -ErrorAction Stop).Source }
$arguments=@('-p', (Join-Path $PSScriptRoot 'android'), 'assembleDebug', '--no-daemon', '--console=plain')
if($Test) { $arguments+='assembleDebugAndroidTest' }
if($env:HTTPS_PROXY) {
    $proxyUri=[uri]$env:HTTPS_PROXY
    if($proxyUri.UserInfo) { throw 'Configure authenticated Gradle proxy separately.' }
    $arguments+="-Dhttps.proxyHost=$($proxyUri.Host)","-Dhttps.proxyPort=$($proxyUri.Port)","-Dhttp.proxyHost=$($proxyUri.Host)","-Dhttp.proxyPort=$($proxyUri.Port)"
}
& $gradle @arguments
if($LASTEXITCODE -ne 0) { throw 'Android build failed.' }
$configuration=Get-Content -LiteralPath "$PSScriptRoot/android/app/build.gradle" -Raw
$version=[regex]::Match($configuration,"versionName '([^']+)'").Groups[1].Value
if(!$version) { throw 'Missing Android version.' }
$destination=Join-Path $PSScriptRoot "dist/OwnVPN-Android-$version.apk"
New-Item -ItemType Directory -Path "$PSScriptRoot/dist" -Force | Out-Null
Copy-Item -LiteralPath "$PSScriptRoot/android/app/build/outputs/apk/debug/app-debug.apk" -Destination $destination -Force
Write-Host "Built: $destination"
if($Install -or $Test) {
    $adb=Join-Path $env:ANDROID_HOME 'platform-tools/adb.exe'
    $deviceArguments=@(); if($DeviceSerial) { $deviceArguments=@('-s',$DeviceSerial) }
    & $adb @deviceArguments install -r $destination
    if($LASTEXITCODE -ne 0) { throw 'APK installation failed. Confirm the phone allows USB installation.' }
    if($Test) {
        & $adb @deviceArguments install -r "$PSScriptRoot/android/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"
        if($LASTEXITCODE -ne 0) { throw 'Test APK installation failed.' }
        & $adb @deviceArguments shell am instrument -w 'com.ownvpn.android.test/com.ownvpn.android.SmokeInstrumentation' | Tee-Object -Variable result
        if($LASTEXITCODE -ne 0 -or ($result -join "`n") -notmatch 'OWNVPN_TESTS_PASSED') { throw 'Android device tests failed.' }
    }
}
