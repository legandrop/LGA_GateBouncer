function Initialize-GBP3BridgeOwn {
    if ('GbP3Bridge' -as [type]) { return }
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class GbP3Bridge {
 [StructLayout(LayoutKind.Sequential)] public struct FileInfo {
  public UInt32 Attr, CreateLo, CreateHi, AccessLo, AccessHi, WriteLo, WriteHi, Volume, SizeHi, SizeLo, Links, IdHi, IdLo;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,UInt32 a,UInt32 s,IntPtr sa,UInt32 d,UInt32 f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out FileInfo i);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern UInt32 GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder b,UInt32 n,UInt32 f);
 public static SafeFileHandle Parent(string p) { return CreateFileW(p,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero); }
 public static FileInfo Inspect(SafeFileHandle h,string path,bool directory) {
  FileInfo i; var b=new StringBuilder(1024); UInt32 n=GetFinalPathNameByHandleW(h,b,1024,0);
  if(h.IsInvalid||h.IsClosed||n==0||n>=1024||b.ToString()!=@"\\?\"+path||!GetFileInformationByHandle(h,out i)||
   (i.Attr&0x400)!=0||((i.Attr&0x10)!=0)!=directory||(!directory&&i.Links!=1)) throw new InvalidOperationException("FileCustodyChanged");
  return i;
 }
 public static bool Same(FileInfo a,FileInfo b) { return a.Volume==b.Volume&&a.IdHi==b.IdHi&&a.IdLo==b.IdLo&&a.SizeHi==b.SizeHi&&a.SizeLo==b.SizeLo&&a.WriteHi==b.WriteHi&&a.WriteLo==b.WriteLo; }
 [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int Current();
 [StructLayout(LayoutKind.Sequential)] public struct Result {
  public UInt32 Magic, Bytes, Completed, Converted, Packets, Records, Header, EventsKnown, EventsLost, BuffersKnown, BuffersLost, EmittedKnown;
  public UInt64 Reserved, Emitted;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] public static extern IntPtr LoadLibraryExW(string path,IntPtr file,UInt32 flags);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern bool FreeLibrary(IntPtr module);
 [DllImport(@"C:\GateBouncerLab\bin\guest_conversion.dll",EntryPoint="GbP3Convert",CallingConvention=CallingConvention.Cdecl,CharSet=CharSet.Unicode)]
 public static extern int Convert(IntPtr input,string run,UInt32 index,Int64 start,Int64 end,byte[] pin,Current current,out Result result);
 [DllImport(@"C:\GateBouncerLab\bin\guest_conversion.dll",EntryPoint="GbP3Drain",CallingConvention=CallingConvention.Cdecl,CharSet=CharSet.Unicode)]
 public static extern int Drain(string run);
}
"@ -ErrorAction Stop
}
function Open-GBPinOwn($c,[string]$path,[string]$expected) {
    Initialize-GBP3BridgeOwn
    if ($expected -cnotmatch '^[0-9A-F]{64}$') { throw 'PackagePinInvalid' }
    $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $c.Pins.Add($stream)
    $c.PinPaths.Add($path)
    $identity=[GbP3Bridge]::Inspect($stream.SafeFileHandle,$path,$false)
    $c.PinIdentities.Add($identity)
    $entry=Get-Item -LiteralPath $path -ErrorAction Stop
    if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $stream.Length -le 0 -or $stream.Length -gt 16777216) { throw 'PackageImageInvalid' }
    $parent=[IO.Path]::GetDirectoryName($path)
    while ($parent) {
        $handle=[GbP3Bridge]::Parent($parent)
        $c.Parents.Add($handle); $c.ParentPaths.Add($parent)
        $null=[GbP3Bridge]::Inspect($handle,$parent,$true)
        $entry=Get-Item -LiteralPath $parent -ErrorAction Stop
        if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'PackageParentInvalid' }
        $parent=[IO.Path]::GetDirectoryName($parent.TrimEnd('\'))
    }
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $actual=([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','') }
    finally { $sha.Dispose(); $stream.Position=0 }
    if ($actual -cne $expected) { throw 'PackagePinChanged' }
    if (-not [GbP3Bridge]::Same($identity,[GbP3Bridge]::Inspect($stream.SafeFileHandle,$path,$false))) { throw 'PackagePinChanged' }
}
function Test-GBConversionCurrentOwn($c) {
    try {
        if (-not [object]::ReferenceEquals($script:Guest,$c) -or -not(Test-GBLive $c) -or
            $c.Stop -cne 'Observed' -or -not $c.FileFinal -or -not $c.FinalStream.CanRead -or
            $c.FinalStream.SafeFileHandle.IsClosed -or $c.FinalStream.Length -ne $c.ETLSize) { return $false }
        $current=Assert-GBOwn $c
        if ($current.State -cne 'Stopped') { return $false }
        & $c.Api 'ValidateNIC' $c | Out-Null
        $boot=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
        if ($boot -cne $c.Profile.BootTime -or [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -cne $c.Profile.GuestUserSID) { return $false }
        for ($i=0;$i -lt $c.Pins.Count;$i++) {
            if (-not $c.Pins[$i].CanRead -or -not [GbP3Bridge]::Same($c.PinIdentities[$i],
                [GbP3Bridge]::Inspect($c.Pins[$i].SafeFileHandle,$c.PinPaths[$i],$false))) { return $false }
        }
        for ($i=0;$i -lt $c.Parents.Count;$i++) { $null=[GbP3Bridge]::Inspect($c.Parents[$i],$c.ParentPaths[$i],$true) }
        if (-not [GbP3Bridge]::Same($c.FinalIdentity,[GbP3Bridge]::Inspect($c.FinalStream.SafeFileHandle,$c.FinalStream.Name,$false))) { return $false }
        return (Test-GBLive $c)
    } catch { return $false }
}
function Invoke-GBConvertOwn($c) {
    if (-not(Test-GBConversionCurrentOwn $c)) { throw 'ConversionOwnerChanged' }
    Initialize-GBP3BridgeOwn
    # DLL ya fijada en el challenge; loader busca dependencias exclusivamente propias/System32.
    if ($c.NativeLibrary -eq [IntPtr]::Zero) {
        $c.NativeLibrary=[GbP3Bridge]::LoadLibraryExW('C:\GateBouncerLab\bin\guest_conversion.dll',[IntPtr]::Zero,0x900)
        if ($c.NativeLibrary -eq [IntPtr]::Zero) { throw 'ConversionLibraryUnknown' }
    }
    $pin=New-Object byte[] 32
    for ($i=0;$i -lt 32;$i++) { $pin[$i]=[Convert]::ToByte($c.Profile.ConverterHash.Substring($i*2,2),16) }
    $callback=[GbP3Bridge+Current]{ if (Test-GBConversionCurrentOwn $c) { return 1 }; return 0 }
    $retained=$false
    $c.ConversionPending=$true
    try {
        $c.FinalStream.SafeFileHandle.DangerousAddRef([ref]$retained)
        $result=[GbP3Bridge+Result]::new()
        $code=[GbP3Bridge]::Convert($c.FinalStream.SafeFileHandle.DangerousGetHandle(),$c.Run,
            [uint32]$c.Profile.Index,$c.StartUtc,$c.StopUtc,$pin,$callback,[ref]$result)
        [GC]::KeepAlive($callback)
        if ($code -eq 2) { throw 'ConversionDrainPending' }
        $c.ConversionPending=$false
        if ($code -ne 0 -or -not(Test-GBConversionCurrentOwn $c)) { throw 'ConversionIncomplete' }
        $c.Conversion=[pscustomobject]@{Outcome='ConvertedOriginalLengthUnknown';Packets=$result.Packets;
            Records=$result.Records;EmittedBytes=$result.Emitted;ReservedBytes=$result.Reserved;
            OriginalLength='Unknown';Retention='Unknown';NativeEventsLost=$result.EventsLost;NativeBuffersLost=$result.BuffersLost}
    } finally { if ($retained) { $c.FinalStream.SafeFileHandle.DangerousRelease() } }
}

# Captura guest propia: importar no inicia cmdlets, CIM, procesos ni captura.
Set-StrictMode -Version Latest
$script:Gates = @{}
$script:Guest = $null
$script:GuestModulePath = 'C:\GateBouncerLab\bin\capture_netevent.psm1'

function New-GBContext($run, $profile, [scriptblock]$api, [scriptblock]$clock) {
    return @{
        Run=$run; Profile=$profile; Api=$api; Clock=$clock; Own=$null; Identity=$null
        Phase='Challenged'; Outcome='NotStarted'; CaptureResult='NotStarted'; Failure='None'
        CreateSubmitted=$false; StartSubmitted=$false; Stop='Pending'; Cleanup='Pending'
        CreatedAt=(& $clock); LastHeartbeat=(& $clock); StartAt=$null; Revoked=$false
        FileFinal=$false; ETLSize=$null; Events=[Collections.Generic.List[object]]::new()
        FinalStream=$null; FinalIdentity=$null; StartUtc=[long]0; StopUtc=[long]0; Conversion=$null; ConversionPending=$false
        Pins=[Collections.Generic.List[object]]::new();PinPaths=[Collections.Generic.List[string]]::new();PinIdentities=[Collections.Generic.List[object]]::new()
        Parents=[Collections.Generic.List[object]]::new();ParentPaths=[Collections.Generic.List[string]]::new();NativeLibrary=[IntPtr]::Zero
    }
}
function Add-GBEvent($c, $kind) {
    if ($c.Events.Count -ge 64) { $c.Revoked=$true; throw 'JournalLimit' }
    if ($kind.Length -gt 128) { $kind=$kind.Substring(0,128) }
    $c.Events.Add([pscustomobject]@{Kind=$kind; At=(& $c.Clock); Phase=$c.Phase})
}
function Test-GBLive($c) {
    $now=& $c.Clock
    return -not $c.Revoked -and $now -ge $c.LastHeartbeat -and
        $now - $c.LastHeartbeat -lt 5 -and $now - $c.CreatedAt -lt 60
}
function Assert-GBOwn($c) {
    if ($null -eq $c.Own -or $null -eq $c.Identity) { throw 'OwnershipUnknown' }
    $current=& $c.Api 'Read' $c
    if ($null -eq $current -or $current.Fingerprint -cne $c.Identity.Fingerprint) {
        $c.Revoked=$true; throw 'OwnershipUnknown'
    }
    return $current
}
function Invoke-GBMutation($c, $action) {
    if ($action -ne 'Stop' -and -not(Test-GBLive $c)) { throw 'AdmissionExpired' }
    $null=Assert-GBOwn $c
    if ($action -ne 'Stop' -and -not(Test-GBLive $c)) { throw 'AdmissionExpired' }
    & $c.Api $action $c | Out-Null
    $current=Assert-GBOwn $c
    if ($action -ne 'Stop' -and -not(Test-GBLive $c)) { throw 'AdmissionExpired' }
    return $current
}
function Get-GBProjection($c) {
    return [pscustomobject]@{
        RunId=$c.Run; Phase=$c.Phase; Outcome=$c.Outcome; StartSubmitted=$c.StartSubmitted
        CreateSubmitted=$c.CreateSubmitted
        CaptureResult=$c.CaptureResult; Failure=$c.Failure
        Stop=$c.Stop; Cleanup=$c.Cleanup; FileFinal=$c.FileFinal; ETLSize=$c.ETLSize
        FileFinalSource='RetainedReadHandleDeniesWriteDelete'; NativeArtifactIdentity='LauncherSeal'
        NativeArtifactAdmitted=$false
        Conversion=$c.Conversion; ConversionPending=$c.ConversionPending
        SessionGuid=$(if($null -ne $c.Identity){$c.Identity.Guid}else{$null})
        IdentityFingerprint=$(if($null -ne $c.Identity){$c.Identity.Fingerprint}else{$null})
        RequestedTraceBufferSize=64; RequestedMaxNumberOfBuffers=64
        ObservedBuffers=$(if($null -ne $c.Identity){$c.Identity.Buffers}else{$null})
        ObservedBuffersSource='CreateCimInstance'
        NativeEventsLost='Unknown'; LogBuffersLost='Unknown'; RealTimeBuffersLost='Unknown'
        Retention='Unknown'; CreatedAt=$c.CreatedAt; StartAt=$c.StartAt; Events=@($c.Events.ToArray())
    }
}
function Invoke-GBLifecycle($c, $step) {
    try {
        if ($step -eq 'Cancel') { $c.Revoked=$true; $c.Outcome='Invalid'; Add-GBEvent $c 'Cancel'; return (Get-GBProjection $c) }
        if ($step -notin @('Stop','Cleanup') -and -not(Test-GBLive $c)) {
            $c.Revoked=$true; throw 'AdmissionExpired'
        }
        switch ($step) {
            Create {
                if ($c.Phase -ne 'Challenged') { throw 'InvalidPhase' }
                if ((& $c.Api 'Resources' $c) -lt 8GB) { throw 'ResourceBlocked' }
                if (@(& $c.Api 'Existing' $c).Count -ne 0) { throw 'ForeignSessionPresent' }
                if (-not(Test-GBLive $c)) { throw 'AdmissionExpired' }
                $c.CreateSubmitted=$true; Add-GBEvent $c 'CreateSubmitted'
                $c.Own=& $c.Api 'Create' $c
                if ($null -eq $c.Own) { throw 'CreateUnknown' }
                $c.Identity=& $c.Api 'Snapshot' $c
                $null=Assert-GBOwn $c
                $c.Phase='Created'; Add-GBEvent $c 'CreateObserved'
            }
            Configure {
                if ($c.Phase -ne 'Created' -or (& $c.Clock)-$c.CreatedAt -ge 10) { throw 'InvalidPhase' }
                $null=Invoke-GBMutation $c 'Provider'
                $null=Invoke-GBMutation $c 'Adapter'
                & $c.Api 'ValidateNIC' $c | Out-Null
                if (-not(Test-GBLive $c)) { throw 'AdmissionExpired' }
                $c.Phase='Configured'; Add-GBEvent $c 'ConfigObserved'
            }
            Start {
                if ($c.Phase -ne 'Configured' -or $c.StartSubmitted) { throw 'InvalidPhase' }
                $null=Assert-GBOwn $c
                & $c.Api 'ValidateNIC' $c | Out-Null
                if ((& $c.Api 'Resources' $c) -lt 8GB -or -not(Test-GBLive $c)) { throw 'ResourceBlocked' }
                $c.StartSubmitted=$true; $c.CaptureResult='Unknown'; $c.StartAt=& $c.Clock; $c.Phase='StartSubmitted'
                $c.StartUtc=[DateTime]::UtcNow.ToFileTimeUtc()
                Add-GBEvent $c 'StartSubmitted' # Irreversible ANTES de intentar el cmdlet.
                $current=Invoke-GBMutation $c 'Start'
                if ($current.State -ne 'Running' -or -not(Test-GBLive $c)) { throw 'StartUnknown' }
                $c.Phase='Running'; $c.CaptureResult='CaptureStarted'; $c.Outcome='CaptureStarted'; Add-GBEvent $c 'StartObserved'
            }
            Status {
                $current=Assert-GBOwn $c
                & $c.Api 'ValidateNIC' $c | Out-Null
                if ((& $c.Api 'Resources' $c) -lt 4GB) { throw 'ResourceBlocked' }
                if ($c.StartSubmitted -and ((& $c.Clock)-$c.StartAt -ge 55 -or $current.State -ne 'Running')) {
                    $c.Revoked=$true; $c.Outcome='Invalid'; Add-GBEvent $c 'StopRequired'
                } else { Add-GBEvent $c 'StatusObserved' }
            }
            Stop {
                if (-not $c.StartSubmitted) { throw 'StartNeverSubmitted' }
                $current=Assert-GBOwn $c
                if ($current.State -eq 'Running') {
                    Add-GBEvent $c 'StopSubmitted'; $current=Invoke-GBMutation $c 'Stop'
                }
                if ($current.State -ne 'Stopped') { throw 'StopUnknown' }
                $c.Stop='Observed'; $c.CaptureResult='Stopped'; $c.Phase='Stopped'; Add-GBEvent $c 'StoppedStateObserved'
                if (-not $c.StopUtc) { $c.StopUtc=[DateTime]::UtcNow.ToFileTimeUtc() }
                $file=& $c.Api 'FinalFile' $c
                $c.ETLSize=$file.Size; $c.FileFinal=$file.Final
                if (-not $file.Final -or $file.Size -le 0 -or $file.Size -gt 8388608 -or
                    (& $c.Clock)-$c.StartAt -ge 60) { throw 'FileOrDeadlineInvalid' }
                $c.Phase='FileFinal'; Add-GBEvent $c 'FileFinalObserved'
            }
            Convert {
                if ($c.Phase -cne 'FileFinal' -or $c.Stop -cne 'Observed' -or -not $c.FileFinal -or
                    -not $c.FinalStream -or $c.Conversion -or $c.ConversionPending) { throw 'ConversionFinalizationMissing' }
                $current=Assert-GBOwn $c
                if ($current.State -cne 'Stopped') { throw 'ConversionStopChanged' }
                Invoke-GBConvertOwn $c
            }
            Cleanup {
                if (-not $c.CreateSubmitted -and $null -eq $c.Own) {
                    $c.Cleanup='NotRequired'; $c.Phase='NoResources'; $c.Revoked=$true
                    if ($c.Outcome -ne 'Invalid') { $c.Outcome='NotStarted' }
                    Add-GBEvent $c 'NoOwnCreateSubmitted'; break
                }
                $current=Assert-GBOwn $c
                if ($c.ConversionPending) {
                    if ([GbP3Bridge]::Drain($c.Run) -ne 0) { throw 'ConversionDrainPending' }
                    $c.ConversionPending=$false
                }
                if ($c.StartSubmitted -and ($c.Stop -ne 'Observed' -or -not $c.FileFinal)) { throw 'StopFinalizationPending' }
                if (($c.StartSubmitted -and $current.State -ne 'Stopped') -or
                    (-not $c.StartSubmitted -and $current.State -notin @('Stopped','Failed'))) { throw 'NotRunningUnknown' }
                Add-GBEvent $c 'CleanupSubmitted'
                & $c.Api 'Remove' $c | Out-Null
                if ($null -ne (& $c.Api 'Read' $c)) { throw 'CleanupUnknown' }
                $c.Cleanup='Observed'; $c.Phase='Removed'; Add-GBEvent $c 'CleanupObserved'
                if (-not $c.StartSubmitted) {
                    if ($c.Failure -eq 'ConfigFailed') { $c.Outcome='ConfigFailed/NotStarted' }
                    elseif ($c.Outcome -ne 'Invalid') { $c.Outcome='NotStarted' }
                    $c.Revoked=$true
                }
            }
            default { throw 'InvalidStep' }
        }
        if ($step -notin @('Stop','Cleanup') -and -not(Test-GBLive $c)) { throw 'AdmissionExpired' }
    } catch {
        $c.Outcome='Invalid'; $c.Revoked=$true
        if ($step -eq 'Configure') { $c.Failure='ConfigFailed' }
        if ($c.Events.Count -lt 64) { Add-GBEvent $c ('Error:'+$_.Exception.Message) }
    }
    return (Get-GBProjection $c)
}
function Close-GBContextFilesOwn($c) {
    if ($c.ConversionPending) {
        if ([GbP3Bridge]::Drain($c.Run) -ne 0) { throw 'ConversionDrainPending' }
        $c.ConversionPending=$false
    }
    if ($c.FinalStream) { $c.FinalStream.Dispose(); $c.FinalStream=$null }
    if ($c.NativeLibrary -ne [IntPtr]::Zero) {
        if (-not [GbP3Bridge]::FreeLibrary($c.NativeLibrary)) { throw 'LibraryCloseUnknown' }
        $c.NativeLibrary=[IntPtr]::Zero
    }
    foreach ($pin in $c.Pins) { $pin.Dispose() }
    $c.Pins.Clear()
    foreach ($parent in $c.Parents) { $parent.Dispose() }
    $c.Parents.Clear()
}
function Get-GBSnapshot($cim, $statusMap) {
    if ($cim -isnot [Microsoft.Management.Infrastructure.CimInstance] -or
        $cim.CimSystemProperties.ClassName -ne 'MSFT_NetEventSession' -or
        $cim.CimSystemProperties.Namespace -ne 'root/standardcimv2') { throw 'CimIdentityUnknown' }
    $guid=[Guid]$cim.Guid
    if ($guid -eq [Guid]::Empty) { throw 'CimGuidUnknown' }
    $keys=@($cim.CimInstanceProperties | Where-Object { $_.Flags.HasFlag([Microsoft.Management.Infrastructure.CimFlags]::Key) } |
        Sort-Object Name | ForEach-Object { $_.Name+'='+[string]$_.Value })
    if ($keys.Count -eq 0 -or -not($keys -contains ('Guid='+[string]$cim.Guid))) { throw 'CimKeysUnknown' }
    $state='Unknown'; $index=[string]$cim.SessionStatus
    if ($statusMap.ContainsKey($index)) { $state=$statusMap[$index] }
    $fingerprint=@($cim.CimSystemProperties.ServerName,$cim.CimSystemProperties.Namespace,
        $cim.CimSystemProperties.ClassName,($keys -join ';'),$cim.InstanceID,$cim.Name,
        $cim.CaptureMode,$cim.LocalFilePath,$cim.MaxFileSize) -join '|'
    if ($fingerprint.Length -gt 4096) { throw 'IdentityLimit' }
    return [pscustomobject]@{Guid=$guid; Fingerprint=$fingerprint; State=$state;
        Buffers=[pscustomobject]@{TraceBufferSize=$cim.TraceBufferSize; MaxNumberOfBuffers=$cim.MaxNumberOfBuffers}}
}
function New-GBNativeAdapter($profile, $statusMap) {
    return {
        param($action,$c)
        $profile=$c.Profile; $statusMap=$c.NativeStatuses
        switch ($action) {
            Resources { return (Get-PSDrive -Name C -PSProvider FileSystem -ErrorAction Stop).Free }
            Existing { return @(NetEventPacketCapture\Get-NetEventSession -ErrorAction Stop) }
            Create {
                $directory='C:\GateBouncerLab\captures\'+$c.Run
                if (Test-Path -LiteralPath $directory) { throw 'RunDirectoryExists' }
                $null=New-Item -ItemType Directory -Path $directory -ErrorAction Stop
                return NetEventPacketCapture\New-NetEventSession -Name 'LGA.GateBouncer.LabCapture' -CaptureMode SaveToFile `
                    -LocalFilePath ($directory+'\capture.etl') -MaxFileSize ([uint32]0) -TraceBufferSize ([uint32]64) `
                    -MaxNumberOfBuffers ([byte]64) -ErrorAction Stop
            }
            Snapshot { return Get-GBSnapshot $c.Own $statusMap }
            Read {
                $current=@(NetEventPacketCapture\Get-NetEventSession -ErrorAction Stop | Where-Object Name -CEQ $c.Own.Name)
                if ($current.Count -eq 0) { return $null }
                if ($current.Count -ne 1) { throw 'AmbiguousSession' }
                return Get-GBSnapshot $current[0] $statusMap
            }
            Provider {
                $ether=[uint16]0x0800
                if ($profile.Local.Contains(':')) { $ether=[uint16]0x86dd }
                $provider=NetEventPacketCapture\Add-NetEventPacketCaptureProvider -SessionName $c.Own.Name -CaptureType Physical `
                    -MultiLayer $false -Level ([byte]4) -EtherType $ether -IpAddresses @($profile.Local,$profile.Peer) `
                    -TruncationLength ([uint16]1536) -ErrorAction Stop
                if ([Guid]$provider.SessionGuid -ne [Guid]$c.Own.Guid -or [Guid]$provider.Guid -eq [Guid]::Empty) { throw 'ProviderBindingUnknown' }
            }
            Adapter { NetEventPacketCapture\Add-NetEventNetworkAdapter -SessionName $c.Own.Name -Name $profile.Name -PromiscuousMode $false -ErrorAction Stop | Out-Null }
            ValidateNIC {
                $nic=Get-NetAdapter -InterfaceIndex $profile.Index -ErrorAction Stop
                $ips=@(Get-NetIPAddress -InterfaceIndex $profile.Index -ErrorAction Stop | ForEach-Object IPAddress)
                if ([Guid]$nic.InterfaceGuid -ne [Guid]$profile.InterfaceGuid -or $nic.Name -cne $profile.Name -or
                    $nic.MacAddress -cne $profile.MAC -or $nic.MtuSize -ne $profile.MTU -or
                    $nic.MtuSize -gt 1500 -or -not($ips -contains $profile.Local)) { throw 'NICChanged' }
            }
            Start { NetEventPacketCapture\Start-NetEventSession -InputObject $c.Own -ErrorAction Stop | Out-Null }
            Stop { NetEventPacketCapture\Stop-NetEventSession -InputObject $c.Own -ErrorAction Stop | Out-Null }
            Remove { NetEventPacketCapture\Remove-NetEventSession -InputObject $c.Own -Confirm:$false -ErrorAction Stop | Out-Null }
            FinalFile {
                $path='C:\GateBouncerLab\captures\'+$c.Run+'\capture.etl'
                if (-not $c.FinalStream) {
                    $c.FinalStream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                    $c.FinalIdentity=[GbP3Bridge]::Inspect($c.FinalStream.SafeFileHandle,$path,$false)
                    $parent=[IO.Path]::GetDirectoryName($path)
                    while ($parent) {
                        $handle=[GbP3Bridge]::Parent($parent)
                        $c.Parents.Add($handle); $c.ParentPaths.Add($parent)
                        $null=[GbP3Bridge]::Inspect($handle,$parent,$true)
                        $parent=[IO.Path]::GetDirectoryName($parent.TrimEnd('\'))
                    }
                }
                if (-not $c.FinalStream.CanRead -or $c.FinalStream.SafeFileHandle.IsClosed) { throw 'FinalStreamLost' }
                return [pscustomobject]@{Size=$c.FinalStream.Length;Final=$true}
            }
            default { throw 'InvalidNativeAction' }
        }
    }
}
function Invoke-GBGuestStep($step, $run, $data) {
    if (-not(Get-Variable PSSenderInfo -ValueOnly -ErrorAction SilentlyContinue)) { throw 'RemoteChannelRequired' }
    if ($step -eq 'Challenge') {
        if ($null -ne $script:Guest) { throw 'GuestContextAlreadyOwned' }
        $profile=$data.Profile
        $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
        try {
            $principal=[Security.Principal.WindowsPrincipal]::new($identity)
            if ($identity.User.Value -cne $profile.GuestUserSID -or
                -not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'GuestRoleChanged' }
        } finally { $identity.Dispose() }


        $boot=(Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o')
        if ($boot -cne $profile.BootTime) { throw 'BootChanged' }
        $inbox=$env:SystemRoot+'\System32\WindowsPowerShell\v1.0\Modules\NetEventPacketCapture\NetEventPacketCapture.psd1'
        if ((Get-FileHash -LiteralPath $inbox -Algorithm SHA256).Hash -cne $profile.InboxModuleHash) { throw 'InboxModuleChanged' }
        $native=Import-Module -Name $inbox -PassThru -ErrorAction Stop
        if ($native.Version.ToString() -cne $profile.InboxModuleVersion) { throw 'InboxVersionChanged' }
        $class=Get-CimClass -Namespace root/standardcimv2 -ClassName MSFT_NetEventSession -ErrorAction Stop
        $map=$class.CimClassProperties['SessionStatus'].Qualifiers['ValueMap'].Value
        $values=$class.CimClassProperties['SessionStatus'].Qualifiers['Values'].Value
        if ($map.Count -ne $values.Count -or $map.Count -gt 16) { throw 'StatusSchemaUnknown' }
        $statuses=@{}; for($i=0;$i -lt $map.Count;$i++) { $statuses[[string]$map[$i]]=[string]$values[$i] }
        if (-not($statuses.Values -contains 'Stopped') -or -not($statuses.Values -contains 'Running')) { throw 'StatusSchemaUnknown' }
        $nonce=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($nonce) } finally { $rng.Dispose() }
        $script:Guest=New-GBContext $run $profile (New-GBNativeAdapter $profile $statuses) {
            [Diagnostics.Stopwatch]::GetTimestamp()/[double][Diagnostics.Stopwatch]::Frequency
        }
        Open-GBPinOwn $script:Guest $script:GuestModulePath $profile.ModuleHash
        Open-GBPinOwn $script:Guest 'C:\GateBouncerLab\bin\conversion_worker.exe' $profile.ConverterHash
        Open-GBPinOwn $script:Guest 'C:\GateBouncerLab\bin\guest_conversion.dll' $profile.LauncherHash
        $script:Guest.NativeStatuses=$statuses
        $script:Guest.HostNonce=$data.HostNonce; $script:Guest.GuestNonce=[Convert]::ToBase64String($nonce)
        try { & $script:Guest.Api 'ValidateNIC' $script:Guest | Out-Null }
        catch { $script:Guest.Revoked=$true; throw }
        return [pscustomobject]@{RunId=$run;HostNonce=$data.HostNonce;GuestNonce=$script:Guest.GuestNonce;BootTime=$boot}
    }
    if ($null -eq $script:Guest -or $script:Guest.Run -cne $run -or
        $data.HostNonce -cne $script:Guest.HostNonce -or $data.GuestNonce -cne $script:Guest.GuestNonce) { throw 'UnknownGuestCapability' }
    # Heartbeat sólo por canal propietario vivo; nunca renueva el límite absoluto.
    if ($step -notin @('Stop','Cleanup','Cancel')) {
        if (-not(Test-GBLive $script:Guest)) { $script:Guest.Revoked=$true }
        else { $script:Guest.LastHeartbeat=& $script:Guest.Clock }
    }
    if ($step -eq 'Cleanup' -and $script:Guest.Phase -in @('Removed','NoResources')) {
        Close-GBContextFilesOwn $script:Guest
        $result=Get-GBProjection $script:Guest
    } else { $result=Invoke-GBLifecycle $script:Guest $step }
    if ($script:Guest.Phase -in @('Removed','NoResources')) {
        Close-GBContextFilesOwn $script:Guest
        $script:Guest=$null
    }
    return $result
}
$script:RemoteStep = {
    param($step,$run,$data)
    $path='C:\GateBouncerLab\bin\capture_netevent.psm1'
    $module=Get-Module | Where-Object Path -CEQ $path
    if ($null -eq $module) { $module=Import-Module -Name $path -PassThru -ErrorAction Stop }
    & $module { param($s,$r,$d) Invoke-GBGuestStep $s $r $d } $step $run $data
}
function Assert-GBSession($record) {
    $session=$record.Session
    if ($session -isnot [System.Management.Automation.Runspaces.PSSession] -or
        $session.Runspace.ConnectionInfo -isnot [System.Management.Automation.Runspaces.VMConnectionInfo] -or
        $session.Runspace.ConnectionInfo.VMGuid -ne $record.VMId -or
        $session.InstanceId -ne $record.Instance -or $session.Runspace.RunspaceStateInfo.State -ne 'Opened') { throw 'OwnedVMChannelLost' }
}
function Test-GBPrivateLiteral([string]$literal) {
    $ip=$null
    if (-not[Net.IPAddress]::TryParse($literal,[ref]$ip) -or $ip.ToString() -cne $literal) { return $false }
    $b=$ip.GetAddressBytes()
    if ($b.Length -eq 16) { return $b[0] -eq 0xfd -and $ip.ScopeId -eq 0 }
    return $b.Length -eq 4 -and ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168))
}
function New-GBCaptureGate {
    param([Parameter(Mandatory)][System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)][Guid]$VMId,[Parameter(Mandatory)][Guid]$AcquisitionRunId,
        [Parameter(Mandatory)][hashtable]$Profile,[Parameter(Mandatory)][System.Threading.CancellationToken]$Cancellation)
    if ($VMId -eq [Guid]::Empty -or $AcquisitionRunId -eq [Guid]::Empty -or $Cancellation.IsCancellationRequested -or $script:Gates.Count -ne 0) { throw 'AdmissionUnavailable' }
    foreach($name in @('ModuleHash','ConverterHash','LauncherHash','InboxModuleHash')) {
        if ($Profile[$name] -cnotmatch '^[0-9A-F]{64}$') { throw 'InvalidBackendIdentity' }
    }
    if ($Profile.ManifestHashes.Count -ne 3 -or @($Profile.ManifestHashes | Select-Object -Unique).Count -ne 3) { throw 'InvalidManifestBundle' }
    foreach($hash in $Profile.ManifestHashes) { if ($hash -cnotmatch '^[0-9A-F]{64}$') { throw 'InvalidManifestBundle' } }
    if ($Profile.GuestUserSID -cnotmatch '^S-1-5-[0-9-]{1,100}$' -or [uint32]$Profile.Index -eq 0 -or
        [Guid]$Profile.InterfaceGuid -eq [Guid]::Empty -or $Profile.Name.Length -gt 128 -or
        $Profile.Name -match '[*?\[\]]' -or $Profile.MTU -le 0 -or $Profile.MTU -gt 1500) { throw 'InvalidGuestProfile' }
    if (-not(Test-GBPrivateLiteral $Profile.Local) -or -not(Test-GBPrivateLiteral $Profile.Peer)) { throw 'InvalidLiteralEndpoints' }
    $a=[Net.IPAddress]::Parse($Profile.Local); $b=[Net.IPAddress]::Parse($Profile.Peer)
    if ($a.AddressFamily -ne $b.AddressFamily -or $a.Equals($b) -or [Net.IPAddress]::IsLoopback($a) -or [Net.IPAddress]::IsLoopback($b)) { throw 'InvalidLiteralEndpoints' }
    $handle=[pscustomobject]@{RunId=$AcquisitionRunId;State='ChannelOwned'}
    $record=@{Handle=$handle;Session=$Session;VMId=$VMId;Instance=$Session.InstanceId;Cancellation=$Cancellation;
        Run=$AcquisitionRunId.ToString('D');HostNonce=$null;GuestNonce=$null;Revoked=$false}
    Assert-GBSession $record
    $nonce=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($nonce) } finally { $rng.Dispose() }
    $record.HostNonce=[Convert]::ToBase64String($nonce)
    $script:Gates[$record.Run]=$record
    try {
    $response=Invoke-Command -Session $Session -ScriptBlock $script:RemoteStep -ArgumentList 'Challenge',$record.Run,@{Profile=$Profile.Clone();HostNonce=$record.HostNonce} -ErrorAction Stop
    Assert-GBSession $record
    if ($Cancellation.IsCancellationRequested -or $response.RunId -cne $record.Run -or
        $response.HostNonce -cne $record.HostNonce -or $response.BootTime -cne $Profile.BootTime -or
        [Convert]::FromBase64String($response.GuestNonce).Length -ne 32) { throw 'ChallengeInvalid' }
    $record.GuestNonce=$response.GuestNonce; $handle.State='Challenged'; $script:Gates[$record.Run]=$record
    return $handle
    } catch { $record.Revoked=$true; $handle.State='Revoked/CleanupPending'; return $handle }
}
function Invoke-GBCaptureStep {
    param([Parameter(Mandatory)][object]$Gate,
        [Parameter(Mandatory)][ValidateSet('Create','Configure','Start','Status','Stop','Convert','Cleanup','Cancel')][string]$Step)
    $record=$script:Gates[[string]$Gate.RunId]
    if ($null -eq $record -or -not[object]::ReferenceEquals($record.Handle,$Gate)) { throw 'ImportedCapabilityDenied' }
    try {
        Assert-GBSession $record
        if ($record.Cancellation.IsCancellationRequested) { $record.Revoked=$true }
        if ($record.Revoked -and $Step -notin @('Stop','Cleanup','Cancel')) { throw 'AdmissionRevoked' }
        $data=@{HostNonce=$record.HostNonce;GuestNonce=$record.GuestNonce}
        if ($record.Revoked -and $Step -ne 'Cancel') {
            Invoke-Command -Session $record.Session -ScriptBlock $script:RemoteStep -ArgumentList 'Cancel',$record.Run,$data -ErrorAction Stop | Out-Null
        }
        $response=Invoke-Command -Session $record.Session -ScriptBlock $script:RemoteStep -ArgumentList $Step,$record.Run,$data -ErrorAction Stop
        Assert-GBSession $record
        if ($record.Cancellation.IsCancellationRequested -and $Step -notin @('Stop','Cleanup','Cancel')) {
            $record.Revoked=$true
            Invoke-Command -Session $record.Session -ScriptBlock $script:RemoteStep -ArgumentList 'Cancel',$record.Run,$data -ErrorAction Stop | Out-Null
            throw [OperationCanceledException]::new('CaptureAdmissionCancelled')
        }
        if ([Text.Encoding]::UTF8.GetByteCount(($response|ConvertTo-Json -Depth 6 -Compress)) -gt 65536) { throw 'ResponseLimit' }
        if ($response.RunId -cne $record.Run) { throw 'ResponseRunMismatch' }
        if ($response.Outcome -eq 'Invalid' -or $Step -eq 'Cancel') { $record.Revoked=$true }
        $Gate.State=$response.Phase
        if ($response.Cleanup -in @('Observed','NotRequired')) { $script:Gates.Remove($record.Run) }
        return $response
    } catch { $record.Revoked=$true; $Gate.State='Revoked/CleanupPending'; throw }
}
Export-ModuleMember -Function New-GBCaptureGate,Invoke-GBCaptureStep
