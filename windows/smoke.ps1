$ErrorActionPreference='Stop'
$dir=(Resolve-Path (Join-Path $PSScriptRoot '..\dist\windows-x64')).Path
if (!(Test-Path env:GITHUB_ACTIONS)) {throw 'Run this smoke test on a disposable CI runner'}
& {
    $ui=Start-Process (Join-Path $dir 'AI Exit Guard.exe') -PassThru
    try {
        if(!$ui.WaitForInputIdle(15000)){throw 'Windows UI failed to initialize'}
        Add-Type -AssemblyName UIAutomationClient
        $id=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ProcessIdProperty,$ui.Id)
        $title=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::NameProperty,'AI Exit Guard')
        $window=$null
        $deadline=[DateTime]::UtcNow.AddSeconds(15)
        while (!$window -and !$ui.HasExited -and [DateTime]::UtcNow -lt $deadline) {
            $condition=New-Object Windows.Automation.AndCondition($id,$title)
            $window=[Windows.Automation.AutomationElement]::RootElement.FindFirst([Windows.Automation.TreeScope]::Children,$condition)
            if(!$window){Start-Sleep -Milliseconds 200}
        }
        if(!$window){throw 'Windows form missing from native accessibility tree'}
        $edits=New-Object Windows.Automation.PropertyCondition([Windows.Automation.AutomationElement]::ControlTypeProperty,[Windows.Automation.ControlType]::Edit)
        if($window.FindAll([Windows.Automation.TreeScope]::Descendants,$edits).Count -ne 8){throw 'Missing proxy fields'}
    } finally {if(!$ui.HasExited){$ui.Kill();$ui.WaitForExit()}}
    $profile=Get-Content -Raw (Join-Path $dir 'AI Exit Guard.pbprofile') | ConvertFrom-Json
    if($profile.ProxyConfigs[0].Host -ne '127.0.0.1' -or $profile.ProxyConfigs[0].Port -ne '39178'){throw 'Wrong relay'}
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=Join-Path $dir 'guard-core.exe';$psi.Arguments='desktop-relay'
    $psi.UseShellExecute=$false;$psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true
    $p=[Diagnostics.Process]::Start($psi)
    try {
        $p.StandardInput.WriteLine('{"Common":{"Scheme":"http","Host":"127.0.0.1","Port":1},"Expected":"192.0.2.1","Profiles":{}}')
        $ready=$p.StandardOutput.ReadLineAsync()
        if(!$ready.Wait(8000) -or $ready.Result -ne 'READY'){throw 'Relay did not start'}
        $tcp=New-Object Net.Sockets.TcpClient('127.0.0.1',39178)
        try {
            $stream=$tcp.GetStream();$stream.ReadTimeout=5000
            $bytes=[Text.Encoding]::ASCII.GetBytes("CONNECT api.openai.com:443 HTTP/1.1"+[Environment]::NewLine+"Host: api.openai.com:443"+[Environment]::NewLine+[Environment]::NewLine)
            $stream.Write($bytes,0,$bytes.Length)
            $reader=New-Object IO.StreamReader($stream)
            if($reader.ReadLine() -notmatch '^HTTP/1\.1 503'){throw 'An unchecked route was allowed'}
        } finally {$tcp.Dispose()}
    } finally {$p.StandardInput.Close();if(!$p.WaitForExit(10000)){$p.Kill();throw 'Relay survived controller shutdown'}}
    Write-Host 'Windows GUI, system profile, closed relay, and controller shutdown passed'
}
