$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$jdk=$env:JAVA_HOME
if(-not $jdk){$jdk=[Environment]::GetEnvironmentVariable('JAVA_HOME','User')}
if(-not $jdk){throw 'Set JAVA_HOME to a JDK 17 or newer.'}
$output=Join-Path $projectRoot 'build/android-import-tests'
New-Item -ItemType Directory -Path $output -Force | Out-Null
& "$jdk/bin/javac.exe" --release 17 -encoding UTF-8 -d $output `
    "$projectRoot/android/app/src/main/java/com/ownvpn/android/ImportWorkspace.java" `
    "$projectRoot/tests/android/ImportWorkspaceTests.java"
if($LASTEXITCODE -ne 0){throw 'Android import host tests did not compile.'}
& "$jdk/bin/java.exe" -cp $output com.ownvpn.android.ImportWorkspaceTests
if($LASTEXITCODE -ne 0){throw 'Android import host tests failed.'}
