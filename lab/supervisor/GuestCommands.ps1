# Comandos constantes: se envian exclusivamente al runspace guest propio.
$script:GbBootstrapCommand = {
    param([string]$Challenge)
    if ($Challenge -cnotmatch '^[0-9a-f]{64}$') { throw 'ChallengeInvalid' }
    $boot = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $nics = @(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
        if (([string]$_.Name).Length -gt 256) { throw 'InterfaceNameBudgetExceeded' }
        [pscustomobject]@{ Guid = [guid]$_.InterfaceGuid; Index = [int]$_.ifIndex;
            Name = [string]$_.Name; Mac = ([string]$_.MacAddress -replace '[-:]','').ToUpperInvariant() }
    })
    if ($nics.Count -gt 16) { throw 'InterfaceBudgetExceeded' }
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    [pscustomobject]@{ Challenge = $Challenge;
        GuestNonce = ([BitConverter]::ToString($bytes) -replace '-','').ToLowerInvariant();
        Boot = $boot.LastBootUpTime.ToUniversalTime().Ticks; Nics = $nics;
        UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value;
        Hash = (Get-FileHash -LiteralPath 'C:\GateBouncerLab\supervisor\GuestCommands.ps1' -Algorithm SHA256 -ErrorAction Stop).Hash }
}

# La tabla fija no recibe scripts, cmdlets, nombres ni rutas del consumidor.
$script:GbCaptureSteps = @{
    PrepareCapture = @('Create','Configure'); StartCapture = @('Start')
    CaptureStatus = @('Status'); StopCapture = @('Stop'); CleanupCapture = @('Cleanup')
}
$script:GbRequiredComponents = @('LinuxChannel','GuestLaunchers','WfpActor','GuestBase','CaptureModule')
$script:GbCapturePhases = @{ Create=@('Created'); Configure=@('Configured'); Start=@('StartSubmitted','Running');
    Status=@('Challenged','Created','Configured','StartSubmitted','Running','Stopped','FileFinal','Removed','NoResources');
    Stop=@('Stopped','FileFinal'); Cleanup=@('Removed','NoResources') }
