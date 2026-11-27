$ErrorActionPreference='Stop'
$dir=(Resolve-Path (Join-Path $PSScriptRoot '..\dist\windows-x64')).Path
if (!(Test-Path env:GITHUB_ACTIONS)) {throw 'Run this smoke test on a disposable CI runner'}
& {
    $ui=Start-Process (Join-Path $dir 'AI Exit Guard.exe') -ArgumentList '--smoke-test' -PassThru
    if(!$ui.WaitForExit(65000)){$ui.Kill();throw 'GUI smoke timed out'}
    if($ui.ExitCode -ne 0){
        if($env:GUARD_UI_SCREENSHOTS -and (Test-Path (Join-Path $env:GUARD_UI_SCREENSHOTS 'webview2-error.txt'))){
            Write-Host (Get-Content -Raw (Join-Path $env:GUARD_UI_SCREENSHOTS 'webview2-error.txt'))
        }
        throw "Native form test failed at stage $($ui.ExitCode)"
    }
    $profile=Get-Content -Raw (Join-Path $dir 'AI Exit Guard.pbprofile') | ConvertFrom-Json
    if($profile.ProxyConfigs[0].Host -ne '127.0.0.1' -or $profile.ProxyConfigs[0].Port -ne '39178'){throw 'Wrong relay'}
    $agRaw=& (Join-Path $dir 'guard-core.exe') antigravity-status
    if($LASTEXITCODE -ne 0){throw "antigravity-status failed with exit code $LASTEXITCODE"}
    $ag=$agRaw | ConvertFrom-Json
    if($ag.state -ne 'missing' -or $ag.rc -ne 0){throw "Unexpected antigravity-status output: $agRaw"}
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=Join-Path $dir 'guard-core.exe';$psi.Arguments='desktop-relay'
    $psi.UseShellExecute=$false;$psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true
    $p=[Diagnostics.Process]::Start($psi)
    try {
        $p.StandardInput.WriteLine('{"Common":{"Scheme":"http","Host":"127.0.0.1","Port":1},"Expected":"192.0.2.1","Profiles":{}}')
        $p.StandardInput.Flush()
        $ready=$p.StandardOutput.ReadLineAsync()
        if(!$ready.Wait(8000) -or $ready.Result -ne 'READY'){throw "Relay did not start (exited=$($p.HasExited), code=$($p.ExitCode), status=$($ready.Status))"}
        $tcp=New-Object Net.Sockets.TcpClient('127.0.0.1',39178)
        try {
            $stream=$tcp.GetStream();$stream.ReadTimeout=5000
            $bytes=[Text.Encoding]::ASCII.GetBytes("CONNECT api.openai.com:443 HTTP/1.1"+[Environment]::NewLine+"Host: api.openai.com:443"+[Environment]::NewLine+[Environment]::NewLine)
            $stream.Write($bytes,0,$bytes.Length)
            $reader=New-Object IO.StreamReader($stream)
            if($reader.ReadLine() -notmatch '^HTTP/1\.1 503'){throw 'An unchecked route was allowed'}
        } finally {$tcp.Dispose()}
    } finally {$p.StandardInput.Close();if(!$p.WaitForExit(10000)){$p.Kill();throw 'Relay survived controller shutdown'}}
    # The same unreachable upstream yields 502 in proxy-only mode. A 503 would
    # indicate a closed diagnostic gate, and 200 would indicate a direct route.
    $p=[Diagnostics.Process]::Start($psi)
    try {
        $p.StandardInput.WriteLine('{"Common":{"Scheme":"http","Host":"127.0.0.1","Port":1},"Expected":"","Profiles":{},"ProxyOnly":true}')
        $p.StandardInput.Flush()
        $ready=$p.StandardOutput.ReadLineAsync()
        if(!$ready.Wait(8000) -or $ready.Result -ne 'READY'){throw 'Proxy-only relay unavailable'}
        $tcp=New-Object Net.Sockets.TcpClient('127.0.0.1',39178)
        try{
            $stream=$tcp.GetStream();$stream.ReadTimeout=5000
            $request=[Text.Encoding]::ASCII.GetBytes("CONNECT api.openai.com:443 HTTP/1.1`r`nHost: api.openai.com:443`r`n`r`n")
            $stream.Write($request,0,$request.Length)
            $reader=New-Object IO.StreamReader($stream)
            if($reader.ReadLine() -notmatch '^HTTP/1\.1 502'){throw 'Wrong upstream failure in proxy-only mode'}
            $p.StandardInput.WriteLine("activity");$p.StandardInput.Flush()
            $report=$p.StandardOutput.ReadLineAsync()
            if(!$report.Wait(5000) -or !$report.Result.StartsWith("FLOWS ")){throw 'Activity response missing'}
            $events=ConvertFrom-Json $report.Result.Substring(6)
            if(!($events | Where-Object {$_.Domain -eq "api.openai.com" -and $_.Status -eq "failed"})){throw 'Failed tunnel absent from activity'}

        }finally{$tcp.Dispose()}
    }finally{$p.StandardInput.Close();if(!$p.WaitForExit(10000)){$p.Kill();throw 'Proxy-only relay failed to stop'}}
    # Exercise the actual OS resolver transaction on this disposable Windows host.
    $uiExe=Join-Path $dir 'AI Exit Guard.exe'
    try {
        $on=Start-Process $uiExe -ArgumentList '--domains-on' -PassThru
        if(!$on.WaitForExit(10000) -or $on.ExitCode){throw 'Windows hosts activation failed'}
        $addrs=[Net.Dns]::GetHostAddresses('daily-cloudcode-pa.googleapis.com')
        if(!$addrs.Count){throw 'No protected DNS answer'}
        foreach($addr in $addrs){if($addr.MapToIPv4().ToString() -ne '127.0.0.2'){throw 'Unexpected nonlocal route'}}
    }finally{
        $off=Start-Process $uiExe -ArgumentList '--domains-off' -PassThru
        if(!$off.WaitForExit(10000) -or $off.ExitCode){throw 'Windows hosts rollback failed'}
    }
    Write-Host 'Windows GUI, system profile, closed relay, and controller shutdown passed'
}
