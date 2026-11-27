param([string]$Output = (Join-Path $PSScriptRoot '..\dist\windows-x64'))
$ErrorActionPreference='Stop'
$versionSource=$null
$hostsFile=$null
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
    $hostsFile=Join-Path ([IO.Path]::GetTempPath()) (([guid]::NewGuid()).ToString()+'.txt')
    $names=& $core system-hosts
    if($LASTEXITCODE){throw 'Domain list generation failed'}
    [IO.File]::WriteAllLines($hostsFile,[string[]]$names)
    $csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    [xml]$plist=Get-Content -Raw -Encoding UTF8 Info.plist
    $version=$plist.SelectSingleNode("/plist/dict/key[text()='CFBundleShortVersionString']/following-sibling::*[1]").InnerText
    $build=$plist.SelectSingleNode("/plist/dict/key[text()='CFBundleVersion']/following-sibling::*[1]").InnerText
    if($version -notmatch '^\d+\.\d+\.\d+$' -or $build -notmatch '^\d+$'){throw 'Invalid version in Info.plist'}
    $versionSource=Join-Path ([IO.Path]::GetTempPath()) (([guid]::NewGuid()).ToString()+'.cs')
    [IO.File]::WriteAllText($versionSource, @"
using System.Reflection;
[assembly: AssemblyInformationalVersion("$version")]
[assembly: AssemblyFileVersion("$version.$build")]
"@)
    $wvVersion='1.0.2903.40'
    $wvCache=Join-Path $PSScriptRoot ".cache\webview2-$wvVersion"
    $wvCore=Join-Path $wvCache 'Microsoft.Web.WebView2.Core.dll'
    $wvWinForms=Join-Path $wvCache 'Microsoft.Web.WebView2.WinForms.dll'
    $wvLoader=Join-Path $wvCache 'WebView2Loader.dll'
    if(!(Test-Path $wvCore) -or !(Test-Path $wvWinForms) -or !(Test-Path $wvLoader)){
        New-Item -ItemType Directory -Force $wvCache | Out-Null
        $nupkg=Join-Path $wvCache 'webview2.nupkg.zip'
        [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -UseBasicParsing -Uri "https://www.nuget.org/api/v2/package/Microsoft.Web.WebView2/$wvVersion" -OutFile $nupkg
        $extract=Join-Path $wvCache 'pkg'
        if(Test-Path $extract){Remove-Item -Recurse -Force $extract}
        Expand-Archive -Path $nupkg -DestinationPath $extract -Force
        Copy-Item (Join-Path $extract 'lib\net462\Microsoft.Web.WebView2.Core.dll') $wvCore -Force
        Copy-Item (Join-Path $extract 'lib\net462\Microsoft.Web.WebView2.WinForms.dll') $wvWinForms -Force
        Copy-Item (Join-Path $extract 'runtimes\win-x64\native\WebView2Loader.dll') $wvLoader -Force
        Remove-Item -Recurse -Force $extract,$nupkg
    }
    Copy-Item $wvCore,$wvWinForms,$wvLoader $Output -Force
    & $csc /nologo /warnaserror /target:winexe /win32manifest:windows\Guard.manifest /platform:x64 /codepage:65001 "/out:$Output\AI Exit Guard.exe" /reference:System.Windows.Forms.dll,System.Drawing.dll,System.Security.dll,System.Web.Extensions.dll,Microsoft.CSharp.dll "/reference:$wvCore" "/reference:$wvWinForms" "/resource:$hostsFile,guard-hosts" "/resource:windows\ui.html,guard-ui.html" windows\Guard.cs windows\Connections.cs windows\DomainLock.cs windows\ClientLock.cs $versionSource
    if($LASTEXITCODE){throw 'Windows UI build failed'}
    $metadata=[Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $Output 'AI Exit Guard.exe'))
    if($metadata.ProductVersion -ne $version -or $metadata.FileVersion -ne "$version.$build"){throw 'Windows version metadata does not match Info.plist'}
    Copy-Item windows\README.txt $Output
} finally {
    foreach($temp in @($hostsFile,$versionSource)){if($temp -and (Test-Path $temp)){Remove-Item $temp}}
    Pop-Location
}
