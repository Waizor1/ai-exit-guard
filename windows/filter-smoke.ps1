$ErrorActionPreference='Stop'
if (!(Test-Path env:GITHUB_ACTIONS)) { throw 'Use a disposable Windows runner' }
$stage=New-Item -ItemType Directory (Join-Path $env:RUNNER_TEMP ('guard-filter-'+[Guid]::NewGuid()))
$installer=Join-Path $stage 'official-setup.exe'
Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/InterceptSuite/ProxyBridge/releases/download/v4.3.0_Windows/ProxyBridge-Setup-4.3.0.exe' -OutFile $installer
if ((Get-FileHash $installer).Hash -ne '64992B813E4B406466540F7CC01332EF90FFE3B234719694347175FD85A3F1F9'){throw 'Unexpected driver distribution'}
$p=Start-Process $installer -ArgumentList '/S' -PassThru -Wait
if($p.ExitCode){throw 'Driver installation failed'}
$exe=Join-Path $env:ProgramFiles 'ProxyBridge\ProxyBridge_CLI.exe'
$profile=(Resolve-Path (Join-Path $PSScriptRoot '..\dist\windows-x64\AI Exit Guard.pbprofile')).Path
$engine=Start-Process $exe -ArgumentList ('--profile "'+$profile+'" --verbose 1') -RedirectStandardOutput (Join-Path $stage 'engine.log') -RedirectStandardError (Join-Path $stage 'engine.err') -PassThru
$listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,39178)
try {
    $listener.Start()
    $protected=Join-Path $stage 'codex.exe'
    Copy-Item (Join-Path $env:WINDIR 'System32\curl.exe') $protected
    # No credentials or AI payload. TEST-NET-1 is a reserved, unroutable origin.
    $arrived=$false
    for($attempt=0;$attempt -lt 12 -and !$arrived;$attempt++){
        if($engine.HasExited){throw 'System filter exited before validation'}
        $probe=Start-Process $protected -ArgumentList '--disable --noproxy "*" -ksS --connect-timeout 2 --max-time 3 https://192.0.2.9' -PassThru -WindowStyle Hidden
        try{
            $until=[DateTime]::UtcNow.AddSeconds(3)
            while(!$listener.Pending() -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 100}
            if($listener.Pending()){
                $peer=$listener.AcceptTcpClient()
                try {
                    $stream=$peer.GetStream();$stream.ReadTimeout=3000
                    $reader=New-Object IO.StreamReader($stream)
                    if($reader.ReadLine() -ne 'CONNECT 192.0.2.9:443 HTTP/1.1'){throw 'Wrong CONNECT destination'}
                    $arrived=$true
                } finally {$peer.Close()}
            }
        } finally {if(!$probe.WaitForExit(4500)){$probe.Kill()}}
    }
    if(!$arrived){throw 'The real protecting driver did not redirect the unconfigured client to Guard'}
    Write-Host 'Verified Windows driver routes a protected executable to Guard'
} finally {$listener.Stop();if(!$engine.HasExited){$engine.Kill();$engine.WaitForExit()}}
