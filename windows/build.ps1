param([string]$Output = (Join-Path $PSScriptRoot '..\dist\windows-x64'))
$ErrorActionPreference='Stop'
Push-Location (Join-Path $PSScriptRoot '..')
try {
    New-Item -ItemType Directory -Force $Output | Out-Null
    $Output=(Resolve-Path $Output).Path
    $env:GOOS='windows'; $env:GOARCH='amd64'; $env:CGO_ENABLED='0'
    $core=Join-Path $Output 'guard-core.exe'
    go build -trimpath '-ldflags=-s -w' -o $core .
    if($LASTEXITCODE){throw 'Go build failed'}
    $profile=& $core system-profile
    if($LASTEXITCODE){throw 'Profile generation failed'}
    [IO.File]::WriteAllText((Join-Path $Output 'AI Exit Guard.pbprofile'),$profile,(New-Object Text.UTF8Encoding($false)))
    $csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    & $csc /nologo /warnaserror /target:winexe /platform:x64 /codepage:65001 "/out:$Output\AI Exit Guard.exe" /reference:System.Windows.Forms.dll,System.Drawing.dll,System.Security.dll,System.Web.Extensions.dll windows\Guard.cs
    if($LASTEXITCODE){throw 'Windows UI build failed'}
    Copy-Item windows\README.txt $Output
} finally {Pop-Location}
