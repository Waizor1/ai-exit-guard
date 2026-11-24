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
# Use a public documentation domain as a stand-in so a failed redirect can
# never send a probe to a real AI account service from the CI runner.
$fixture = Get-Content -Raw $profile | ConvertFrom-Json
$rule = @($fixture.ProxyRules | Where-Object {$_.TargetDomains -eq 'openai.com' -and $_.Action -eq 'PROXY'})
if($rule.Count -ne 1 -or ($fixture.ProxyRules | Where-Object {$_.TargetDomains -eq '*'})){throw 'Expected destination-scoped rules'}
$rule[0].TargetDomains='example.com'
$profile=Join-Path $stage 'fixture.pbprofile'
[IO.File]::WriteAllText($profile,($fixture | ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($false)))
$engine=Start-Process $exe -ArgumentList ('--profile "'+$profile+'" --verbose 1') -RedirectStandardOutput (Join-Path $stage 'engine.log') -RedirectStandardError (Join-Path $stage 'engine.err') -PassThru
$listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,39178)
try {
    $listener.Start()
    $protected=Join-Path $stage 'codex.exe'
    Copy-Item (Join-Path $env:WINDIR 'System32\curl.exe') $protected
    # Only the hostname differs from the production rule.
    $arrived=$false
    for($attempt=0;$attempt -lt 12 -and !$arrived;$attempt++){
        if($engine.HasExited){throw 'System filter exited before validation'}
        $probe=Start-Process $protected -ArgumentList '--disable --noproxy "*" -ksS --connect-timeout 2 --max-time 3 https://example.com' -PassThru -WindowStyle Hidden
        try{
            $until=[DateTime]::UtcNow.AddSeconds(3)
            while(!$listener.Pending() -and [DateTime]::UtcNow -lt $until){Start-Sleep -Milliseconds 100}
            if($listener.Pending()){
                $peer=$listener.AcceptTcpClient()
                try {
                    $stream=$peer.GetStream();$stream.ReadTimeout=3000
                    $reader=New-Object IO.StreamReader($stream)
                    if($reader.ReadLine() -ne 'CONNECT example.com:443 HTTP/1.1'){throw 'Wrong CONNECT destination'}
                    $arrived=$true
                } finally {$peer.Close()}
            }
        } finally {if(!$probe.WaitForExit(4500)){$probe.Kill()}}
    }
    if(!$arrived){throw 'The real protecting driver did not redirect the unconfigured client to Guard'}
    & $protected --disable --noproxy '*' --silent --fail --head --max-time 10 https://github.com | Out-Null
    if($LASTEXITCODE -or $listener.Pending()){throw 'Ordinary development traffic was intercepted'}
    Write-Host 'Verified selective domain routing and independent GitHub access from the same program'
} finally {$listener.Stop();if(!$engine.HasExited){$engine.Kill();$engine.WaitForExit()}}

# Recreate one exact legacy rule on the disposable runner, plus an unrelated
# rule in the same group. Upgrade must remove only the old Guard rule.
$gui=(Resolve-Path (Join-Path $PSScriptRoot '..\dist\windows-x64\AI Exit Guard.exe')).Path
$sha=[Security.Cryptography.SHA256]::Create()
try{$digest=$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($protected.ToLowerInvariant()))}finally{$sha.Dispose()}
$legacy='AI Exit Guard '+[BitConverter]::ToString($digest).Replace('-','').Substring(0,24)+' external'
$other='Guard QA '+[Guid]::NewGuid()
try{
    New-NetFirewallRule -DisplayName $legacy -Group 'AI Exit Guard' -Program $protected -Direction Outbound -Action Block -Profile Domain,Private,Public | Out-Null
    New-NetFirewallRule -DisplayName $other -Group 'AI Exit Guard' -Program $protected -Direction Outbound -Action Allow | Out-Null
    $remove=Start-Process $gui -ArgumentList '--remove-legacy-rules' -PassThru -Wait
    if($remove.ExitCode -or (Get-NetFirewallRule -DisplayName $legacy -ErrorAction SilentlyContinue)){throw 'Legacy rule migration failed'}
    if(!(Get-NetFirewallRule -DisplayName $other -ErrorAction SilentlyContinue)){throw 'Migration changed an unrelated rule'}
}finally{
    Get-NetFirewallRule -DisplayName $legacy,$other -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}
