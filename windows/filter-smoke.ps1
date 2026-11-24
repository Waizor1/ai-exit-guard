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

# Verify the durable per-executable switch independently of the redirector.
$gui=(Resolve-Path (Join-Path $PSScriptRoot '..\dist\windows-x64\AI Exit Guard.exe')).Path
& $protected --disable --noproxy '*' --silent --fail --head --max-time 8 https://github.com | Out-Null
if($LASTEXITCODE){throw 'Test client has no baseline direct connection'}
# Hosted images may start with an inactive profile; the product deliberately refuses
# to report firewall protection until all three profiles can enforce its rules.
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
Get-NetFirewallProfile | Select-Object Name,Enabled | Format-Table
$encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($protected))
try {
    $enable=Start-Process $gui -ArgumentList "--client-on $encoded" -Wait -PassThru -RedirectStandardError (Join-Path $stage firewall.err)
    if($enable.ExitCode){Get-Content (Join-Path $stage firewall.err);throw 'Persistent firewall switch failed to enable'}
    $entries=@(Get-NetFirewallRule -Group 'AI Exit Guard' -ErrorAction Stop | Where-Object { ($_ | Get-NetFirewallApplicationFilter).Program -eq $protected })
    & $protected --disable --noproxy '*' --silent --head --max-time 5 https://github.com | Out-Null
    if($LASTEXITCODE -eq 0){throw 'Direct client request passed the persistent firewall'}
    if($entries.Count -ne 3 -or @($entries | Where-Object {$_.Enabled -ne 'True' -or $_.Action -ne 'Block' -or $_.Direction -ne 'Outbound'}).Count){throw 'Incomplete Windows firewall policy'}
} finally {
    $disable=Start-Process $gui -ArgumentList "--client-off $encoded" -Wait -PassThru
    if($disable.ExitCode){throw 'Persistent firewall rollback failed'}
}

& $protected --disable --noproxy '*' --silent --fail --head --max-time 8 https://github.com | Out-Null
if($LASTEXITCODE){throw 'Direct connection did not recover after removing owned rules'}
