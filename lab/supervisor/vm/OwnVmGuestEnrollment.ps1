# Productor propio: importar sólo define operaciones, sin cuentas, archivos ni canales.
function Initialize-VmEnrollmentCustodyOwn {
    if ('GbVmEnrollmentCustody' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class GbVmEnrollmentCustody {
 [StructLayout(LayoutKind.Sequential)] public struct Info {
  public uint Attr, CreateLo, CreateHi, AccessLo, AccessHi, WriteLo, WriteHi, Volume, SizeHi, SizeLo, Links, IdHi, IdLo;
 }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder b,uint n,uint f);
 public static SafeFileHandle Parent(string p) { return CreateFileW(p,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero); }
 public static Info Inspect(SafeFileHandle h,string path,bool directory) {
  Info i; var b=new StringBuilder(1024); uint n=GetFinalPathNameByHandleW(h,b,1024,0);
  if(h.IsInvalid||h.IsClosed||n==0||n>=1024||b.ToString()!=@"\\?\"+path||!GetFileInformationByHandle(h,out i)||
     (i.Attr&0x400)!=0||((i.Attr&0x10)!=0)!=directory||(!directory&&i.Links!=1)) throw new InvalidOperationException("EnrollmentFileChanged");
  return i;
 }
 public static bool Same(Info a,Info b) { return a.Volume==b.Volume&&a.IdHi==b.IdHi&&a.IdLo==b.IdLo&&a.SizeHi==b.SizeHi&&a.SizeLo==b.SizeLo&&a.WriteHi==b.WriteHi&&a.WriteLo==b.WriteLo; }
}
'@ -ErrorAction Stop
}
function Confirm-VmEnrollmentChannelOwn($owner,$channel,[bool]$cleanup=$false) {
    if (-not [object]::ReferenceEquals((Get-VmOwnRecord $owner.Id),$owner) -or
        -not [object]::ReferenceEquals($channel.Owner,$owner) -or
        ($channel.Generation -ne $owner.Generation -and -not ($cleanup -and $owner.Revoked -and
        $owner.GuestEnrollment -and $channel.Generation -eq $owner.GuestEnrollment.Generation -and
        ([object]::ReferenceEquals($channel,$owner.GuestEnrollment.Bootstrap) -or
         [object]::ReferenceEquals($channel,$owner.GuestEnrollment.Channel)))) -or
        $channel.Session -isnot [System.Management.Automation.Runspaces.PSSession]) { throw 'EnrollmentChannelUnknown' }
    $session=$channel.Session
    $connection=$session.Runspace.ConnectionInfo
    if ($connection -isnot [System.Management.Automation.Runspaces.VMConnectionInfo] -or
        $connection.VMGuid -ne $owner.VmId -or $session.InstanceId -ne $channel.Instance -or
        [string]$session.Runspace.RunspaceStateInfo.State -cne 'Opened' -or
        [string]$session.Availability -cne 'Available') { throw 'EnrollmentChannelChanged' }
}
function Open-VmEnrollmentChannelOwn($owner,$credential,$enrollment,[string]$slot) {
    # Registrar la hoja antes del SDK; un canal devuelto tarde nunca queda huérfano.
    $channel=@{Owner=$owner;Generation=$owner.Generation;Session=$null;Instance=[guid]::Empty;
        Resources=[Collections.Generic.List[object]]::new();Submitted=$false;Closed=$false}
    $enrollment[$slot]=$channel
    Test-VmOwnFrame; Confirm-VmStoragePeers $owner
    $channel.Submitted=$true
    & $script:VmGuestCreate $owner.VmId $credential | ForEach-Object {
        $channel.Resources.Add($_); $channel.Session=$_
    }
    Test-VmOwnFrame
    if ($channel.Resources.Count -ne 1 -or $channel.Session -isnot [System.Management.Automation.Runspaces.PSSession]) { throw 'EnrollmentChannelCardinality' }
    $channel.Instance=[guid]$channel.Session.InstanceId
    Confirm-VmEnrollmentChannelOwn $owner $channel
    return $channel
}
function New-VmEnrollmentChallengeOwn {
    $bytes=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    ([BitConverter]::ToString($bytes) -replace '-','').ToLowerInvariant()
}
function Open-VmEnrollmentPackageOwn($owner,$enrollment) {
    Initialize-VmEnrollmentCustodyOwn
    $package=@{Owner=$owner;Generation=$owner.Generation;Complete=$false;Sid='';
        Entries=[Collections.Generic.List[object]]::new();Hashes=[Collections.Generic.List[string]]::new();
        Paths=[Collections.Generic.List[string]]::new();GuestIdentities=$null}
    $owner.GuestPackage=$package; $enrollment.Package=$package
    $root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $sources=@(
        @('bin\guest_broker.exe','C:\GateBouncerLab\bin\guest_broker.exe'),
        @('bin\desktop_worker.exe','C:\GateBouncerLab\bin\desktop_worker.exe'),
        @('supervisor\GuestCommands.ps1','C:\GateBouncerLab\supervisor\GuestCommands.ps1'),
        @('supervisor\capture\capture_netevent.psm1','C:\GateBouncerLab\bin\capture_netevent.psm1'),
        @('bin\guest_conversion.dll','C:\GateBouncerLab\bin\guest_conversion.dll'),
        @('bin\conversion_worker.exe','C:\GateBouncerLab\bin\conversion_worker.exe'))
    foreach ($source in $sources) {
        Test-VmOwnFrame
        $path=[IO.Path]::GetFullPath((Join-Path $root $source[0]))
        $entry=@{Path=$path;Target=$source[1];Stream=$null;Identity=$null;Hash='';
            Parents=[Collections.Generic.List[object]]::new();ParentPaths=[Collections.Generic.List[string]]::new()}
        $package.Entries.Add($entry)
        $entry.Stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $entry.Identity=[GbVmEnrollmentCustody]::Inspect($entry.Stream.SafeFileHandle,$path,$false)
        if ($entry.Stream.Length -le 0 -or $entry.Stream.Length -gt 16777216) { throw 'EnrollmentPackageBudget' }
        $parent=[IO.Path]::GetDirectoryName($path)
        while ($parent) {
            $handle=[GbVmEnrollmentCustody]::Parent($parent)
            $entry.Parents.Add($handle); $entry.ParentPaths.Add($parent)
            $null=[GbVmEnrollmentCustody]::Inspect($handle,$parent,$true)
            $parent=[IO.Path]::GetDirectoryName($parent.TrimEnd('\'))
        }
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $entry.Hash=([BitConverter]::ToString($sha.ComputeHash($entry.Stream)) -replace '-','') }
        finally { $sha.Dispose(); $entry.Stream.Position=0 }
        if (-not [GbVmEnrollmentCustody]::Same($entry.Identity,
            [GbVmEnrollmentCustody]::Inspect($entry.Stream.SafeFileHandle,$path,$false))) { throw 'EnrollmentPackageChanged' }
        $package.Hashes.Add($entry.Hash); $package.Paths.Add($entry.Target)
        Test-VmOwnFrame
    }
    $package.Complete=$true
    return $package
}
function Confirm-VmEnrollmentPackageOwn($owner,[bool]$cleanup=$false) {
    $package=$owner.GuestPackage
    if (-not $package -or -not [object]::ReferenceEquals($package.Owner,$owner) -or
        ($package.Generation -ne $owner.Generation -and -not ($cleanup -and $owner.GuestEnrollment -and
            [object]::ReferenceEquals($owner.GuestEnrollment.Package,$package) -and
            $package.Generation -eq $owner.GuestEnrollment.Generation)) -or -not $package.Complete -or
        $package.Entries.Count -ne 6 -or $package.Hashes.Count -ne 6 -or $package.Paths.Count -ne 6) { throw 'EnrollmentPackageRevoked' }
    foreach ($entry in $package.Entries) {
        if (-not $entry.Stream.CanRead -or -not [GbVmEnrollmentCustody]::Same($entry.Identity,
            [GbVmEnrollmentCustody]::Inspect($entry.Stream.SafeFileHandle,$entry.Path,$false))) { throw 'EnrollmentPackageChanged' }
        for ($i=0;$i -lt $entry.Parents.Count;$i++) {
            $null=[GbVmEnrollmentCustody]::Inspect($entry.Parents[$i],$entry.ParentPaths[$i],$true)
        }
    }
    return $package
}

$script:VmEnrollmentRead={
    param($session,$ownerId,$challenge)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($ownerId,$challenge)
        if ($ownerId -cnotmatch '^[0-9a-f]{32}$' -or $challenge -cnotmatch '^[0-9a-f]{64}$') { throw 'EnrollmentRequestInvalid' }
        $boot=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $nics=@(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{Guid=[guid]$_.InterfaceGuid;Index=[int]$_.ifIndex;Name=[string]$_.Name;
                Mac=([string]$_.MacAddress -replace '[-:]','').ToUpperInvariant()}
        })
        if ($nics.Count -gt 16) { throw 'EnrollmentTopologyBudget' }
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Boot=[long]$boot.LastBootUpTime.ToUniversalTime().Ticks;
            Sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Nics=$nics}
    } -ArgumentList $ownerId,$challenge -ErrorAction Stop
}
function Read-VmEnrollmentBootOwn($owner,$channel,[bool]$cleanup=$false) {
    Confirm-VmEnrollmentChannelOwn $owner $channel $cleanup
    $challenge=New-VmEnrollmentChallengeOwn
    $reply=@(& $script:VmEnrollmentRead $channel.Session $owner.Id.ToString('N') $challenge)
    Test-VmOwnFrame; Confirm-VmStoragePeers $owner; Confirm-VmEnrollmentChannelOwn $owner $channel $cleanup
    if ($reply.Count -ne 1 -or $reply[0].Owner -cne $owner.Id.ToString('N') -or
        $reply[0].Challenge -cne $challenge -or $reply[0].Boot -isnot [long] -or $reply[0].Boot -le 0 -or
        $reply[0].Sid -cnotmatch '^S-1-5-[0-9-]{1,160}$') { throw 'EnrollmentBootUnconfirmed' }
    $adapters=@(Read-VmOwnPort $script:VmAdapters @($owner.Resources[0].Ref))
    if ($adapters.Count -ne 1) { throw 'EnrollmentTopologyChanged' }
    $mac=([string]$adapters[0].MacAddress -replace '[-:]','').ToUpperInvariant()
    $nics=@($reply[0].Nics | Where-Object { $_.Mac -ceq $mac })
    if (@($reply[0].Nics).Count -gt 16 -or $nics.Count -ne 1 -or [guid]$nics[0].Guid -eq [guid]::Empty -or
        [int]$nics[0].Index -le 0 -or ([string]$nics[0].Name).Length -gt 128) { throw 'EnrollmentTopologyChanged' }
    return @{Boot=$reply[0].Boot;Sid=$reply[0].Sid;Nic=$nics[0];Mac=$mac}
}
function Confirm-VmEnrollmentBootPairOwn($left,$right,[bool]$sameSid) {
    if ($left.Boot -ne $right.Boot -or $left.Mac -cne $right.Mac -or
        $left.Nic.Guid -ne $right.Nic.Guid -or $left.Nic.Index -ne $right.Nic.Index -or
        $left.Nic.Name -cne $right.Nic.Name -or ($sameSid -and $left.Sid -cne $right.Sid)) { throw 'EnrollmentBootChanged' }
}

$script:VmEnrollmentInstall={
    param($session,$ownerId,$challenge,$name,$password,$targets,$hashes)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($ownerId,$challenge,$name,$password,$targets,$hashes)
        if ($ownerId -cnotmatch '^[0-9a-f]{32}$' -or $challenge -cnotmatch '^[0-9a-f]{64}$' -or
            $name -cne ('gb'+$ownerId.Substring(0,18)) -or $password -isnot [Security.SecureString] -or
            @($targets).Count -ne 6 -or @($hashes).Count -ne 6) { throw 'EnrollmentInstallInvalid' }
        $fixed=@('C:\GateBouncerLab\bin\guest_broker.exe','C:\GateBouncerLab\bin\desktop_worker.exe',
            'C:\GateBouncerLab\supervisor\GuestCommands.ps1','C:\GateBouncerLab\bin\capture_netevent.psm1',
            'C:\GateBouncerLab\bin\guest_conversion.dll','C:\GateBouncerLab\bin\conversion_worker.exe')
        for ($i=0;$i -lt 6;$i++) {
            if ($targets[$i] -cne $fixed[$i] -or $hashes[$i] -cnotmatch '^[0-9A-F]{64}$') { throw 'EnrollmentPackageInvalid' }
        }
        if (Get-Variable -Name GbVmEnrollmentAttempt -Scope Global -ErrorAction SilentlyContinue) { throw 'EnrollmentInstallReplay' }
        # El intento se conserva incluso si la respuesta o el primer SDK se pierden.
        $global:GbVmEnrollmentAttempt=@{Owner=$ownerId;Name=$name;Sid='';AccountSubmitted=$false;
            GroupSubmitted=$false;Directories=[Collections.Generic.List[string]]::new();
            Targets=$fixed;Hashes=$hashes;Writes=[Collections.Generic.List[object]]::new();
            Complete=$false;Disabled=$false;Account=$null;Password=$null}
        $attempt=$global:GbVmEnrollmentAttempt
        if (-not ('GbVmEnrollmentWrittenFile' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class GbVmEnrollmentWrittenFile {
 [StructLayout(LayoutKind.Sequential)] public struct Info {
  public uint Attr, CreateLo, CreateHi, AccessLo, AccessHi, WriteLo, WriteHi, Volume, SizeHi, SizeLo, Links, IdHi, IdLo;
 }
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 public static Info Inspect(SafeFileHandle h) {
  Info i;
  if(h.IsInvalid||h.IsClosed||!GetFileInformationByHandle(h,out i)||i.Links!=1||(i.Attr&0x410)!=0)
   throw new InvalidOperationException("EnrollmentWriterIdentityUnknown");
  return i;
 }
}
'@ -ErrorAction Stop
        }
        if (Test-Path -LiteralPath 'C:\GateBouncerLab' -ErrorAction Stop) { throw 'EnrollmentRootPreexisting' }
        if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) { throw 'EnrollmentAccountPreexisting' }
        $attempt.AccountSubmitted=$true
        $account=New-LocalUser -Name $name -Password $password -Description ('GateBouncer guest '+$ownerId) -ErrorAction Stop
        $attempt.Account=$account
        if ($account -isnot [Microsoft.PowerShell.Commands.LocalUser] -or $account.Name -cne $name -or
            $account.SID.Value -cnotmatch '^S-1-5-21-[0-9-]+$') { throw 'EnrollmentAccountUnconfirmed' }
        $attempt.Sid=$account.SID.Value
        # PowerShell Direct requiere una cuenta administradora; sólo dentro de esta VM propia.
        $group=Get-LocalGroup -SID ([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')) -ErrorAction Stop
        $attempt.GroupSubmitted=$true
        Add-LocalGroupMember -Group $group -Member $account -ErrorAction Stop
        $members=@(Get-LocalGroupMember -Group $group -ErrorAction Stop | Where-Object { $_.SID.Value -ceq $attempt.Sid })
        if ($members.Count -ne 1) { throw 'EnrollmentGroupUnconfirmed' }
        foreach ($path in @('C:\GateBouncerLab','C:\GateBouncerLab\bin','C:\GateBouncerLab\supervisor')) {
            $attempt.Directories.Add($path)
            $null=New-Item -ItemType Directory -Path $path -ErrorAction Stop
            $entry=Get-Item -LiteralPath $path -ErrorAction Stop
            if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'EnrollmentDirectoryChanged' }
        }
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Sid=$attempt.Sid;Prepared=$true}
    } -ArgumentList $ownerId,$challenge,$name,$password,$targets,$hashes -ErrorAction Stop
}
$script:VmEnrollmentWrite={
    param($session,$ownerId,$challenge,$index,$bytes)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($ownerId,$challenge,$index,$bytes)
        $a=$global:GbVmEnrollmentAttempt
        if (-not $a -or $a.Owner -cne $ownerId -or $a.Complete -or $challenge -cnotmatch '^[0-9a-f]{64}$' -or
            $index -ne $a.Writes.Count -or $index -lt 0 -or $index -gt 5 -or $bytes -isnot [byte[]] -or
            $bytes.Length -le 0 -or $bytes.Length -gt 16777216) { throw 'EnrollmentWriteInvalid' }
        # No sobrescribe archivos ajenos; slot custodiado antes de CreateNew/Flush.
        $slot=@{Path=$a.Targets[$index];Submitted=$false;Stream=$null;Written=$false;Identity=$null}
        $a.Writes.Add($slot); $slot.Submitted=$true
        $slot.Stream=[IO.File]::Open($slot.Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read)
        $slot.Stream.Write($bytes,0,$bytes.Length); $slot.Stream.Flush($true); $slot.Stream.Position=0
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $actual=([BitConverter]::ToString($sha.ComputeHash($slot.Stream)) -replace '-','') }
        finally { $sha.Dispose(); $slot.Stream.Position=0 }
        if ($actual -cne $a.Hashes[$index]) { throw 'EnrollmentWriteChanged' }
        $slot.Identity=[GbVmEnrollmentWrittenFile]::Inspect($slot.Stream.SafeFileHandle)
        $slot.Written=$true
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Index=[int]$index;Hash=$actual;Written=$true}
    } -ArgumentList $ownerId,$challenge,$index,$bytes -ErrorAction Stop
}
$script:VmEnrollmentSeal={
    param($session,$ownerId,$challenge)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($ownerId,$challenge)
        $a=$global:GbVmEnrollmentAttempt
        if (-not $a -or $a.Owner -cne $ownerId -or $a.Complete -or $a.Writes.Count -ne 6 -or
            $challenge -cnotmatch '^[0-9a-f]{64}$') { throw 'EnrollmentSealInvalid' }
        foreach ($slot in $a.Writes) {
            if (-not $slot.Written -or -not $slot.Stream.CanRead) { throw 'EnrollmentSealIncomplete' }
            $slot.Stream.Dispose(); $slot.Stream=$null
        }
        $a.Complete=$true
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Sid=$a.Sid;Sealed=$true;
            Files=@($a.Writes | ForEach-Object { [pscustomobject]@{Volume=[uint32]$_.Identity.Volume;
                IdHi=[uint32]$_.Identity.IdHi;IdLo=[uint32]$_.Identity.IdLo} })}
    } -ArgumentList $ownerId,$challenge -ErrorAction Stop
}
function Invoke-VmEnrollmentEffectOwn($owner,$enrollment,[scriptblock]$port,[object[]]$arguments) {
    Test-VmOwnFrame; Confirm-VmStoragePeers $owner
    Confirm-VmEnrollmentChannelOwn $owner $enrollment.Bootstrap
    $null=Confirm-VmEnrollmentPackageOwn $owner
    $before=Read-VmEnrollmentBootOwn $owner $enrollment.Bootstrap
    Confirm-VmEnrollmentBootPairOwn $enrollment.BootstrapObservation $before $true
    if ($enrollment.Revoked -or $owner.Revoked -or $enrollment.Generation -ne $owner.Generation) { throw 'EnrollmentRevoked' }
    # Un retorno tardío queda capturado antes de volver a comprobar guards.
    $attempt=@{Submitted=$false;Outputs=[Collections.Generic.List[object]]::new();Confirmed=$false}
    $enrollment.Attempts.Add($attempt); $attempt.Submitted=$true
    if ([object]::ReferenceEquals($port,$script:VmEnrollmentInstall)) { $enrollment.InstallSubmitted=$true }
    & $port @arguments | ForEach-Object { $attempt.Outputs.Add($_) }
    Test-VmOwnFrame; Confirm-VmStoragePeers $owner
    Confirm-VmEnrollmentChannelOwn $owner $enrollment.Bootstrap
    $null=Confirm-VmEnrollmentPackageOwn $owner
    $after=Read-VmEnrollmentBootOwn $owner $enrollment.Bootstrap
    Confirm-VmEnrollmentBootPairOwn $enrollment.BootstrapObservation $after $true
    if ($enrollment.Revoked -or $owner.Revoked -or $enrollment.Generation -ne $owner.Generation -or
        $attempt.Outputs.Count -ne 1) { throw 'EnrollmentEffectUnconfirmed' }
    $owner.Observed=Read-VmOwnClock
    return $attempt
}
function Confirm-VmGuestEnrollmentOwn($enrollment,[bool]$cleanup=$false) {
    $owner=$enrollment.Owner
    if (-not $owner -or -not [object]::ReferenceEquals((Get-VmOwnRecord $owner.Id),$owner) -or
        -not [object]::ReferenceEquals($owner.GuestEnrollment,$enrollment) -or $owner.Kind -cne 'Windows' -or
        -not [object]::ReferenceEquals($enrollment.Package,$owner.GuestPackage) -or
        -not $owner.Storage -or -not [object]::ReferenceEquals($owner.Storage.Owner,$owner) -or
        $owner.Storage.Phase -cne 'BootRunning' -or -not $owner.Storage.StartSubmitted) { throw 'EnrollmentOwnerUnknown' }
    if (-not $cleanup -and ($owner.Revoked -or $enrollment.Revoked -or -not $enrollment.Confirmed -or
        $owner.Generation -ne $enrollment.Generation)) { throw 'EnrollmentRevoked' }
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    $script:VmBoundary.Busy=$true
    try {
        Enter-VmOwnFrame $owner $cleanup; Test-VmOwnFrame; Confirm-VmStoragePeers $owner
        Confirm-VmEnrollmentChannelOwn $owner $enrollment.Channel $cleanup
        if ($cleanup) {
            # Cleanup usa el canal exacto de la captura ya creada. Perder bootstrap/pin
            # no debe impedir Stop de sus recursos; tampoco admite Create/Start nuevos.
            $right=Read-VmEnrollmentBootOwn $owner $enrollment.Channel $true
            Confirm-VmEnrollmentBootPairOwn $enrollment.AuthenticatedObservation $right $true
        }
        if (-not $cleanup) {
            Confirm-VmEnrollmentChannelOwn $owner $enrollment.Bootstrap
            $null=Confirm-VmEnrollmentPackageOwn $owner
            $left=Read-VmEnrollmentBootOwn $owner $enrollment.Bootstrap
            $right=Read-VmEnrollmentBootOwn $owner $enrollment.Channel
            Confirm-VmEnrollmentBootPairOwn $enrollment.BootstrapObservation $left $true
            Confirm-VmEnrollmentBootPairOwn $enrollment.AuthenticatedObservation $right $true
            Confirm-VmEnrollmentBootPairOwn $left $right $false
            if ($right.Sid -cne $owner.GuestPackage.Sid) { throw 'EnrollmentAccountChanged' }
            # Volver a leer las hojas retenidas por AMBOS canales, además del boot.
            foreach ($channel in @($enrollment.Bootstrap,$enrollment.Channel)) {
                $challenge=New-VmEnrollmentChallengeOwn
                $reply=@(& $script:VmGuestCall $channel.Session 'Observe' $owner.Id.ToString('N') $challenge)
                Test-VmOwnFrame; Confirm-VmEnrollmentChannelOwn $owner $channel
                if ($reply.Count -ne 1 -or $reply[0].Owner -cne $owner.Id.ToString('N') -or
                    $reply[0].Challenge -cne $challenge -or $reply[0].Boot -ne $left.Boot -or
                    @($reply[0].Hashes).Count -ne 6 -or @($reply[0].Files).Count -ne 6) { throw 'EnrollmentPinsLost' }
                for ($i=0;$i -lt 6;$i++) {
                    $file=$owner.GuestPackage.GuestIdentities[$i]; $actual=$reply[0].Files[$i]
                    if ($reply[0].Hashes[$i] -cne $owner.GuestPackage.Hashes[$i] -or
                        $file.Volume -ne $actual.Volume -or $file.IdHi -ne $actual.IdHi -or
                        $file.IdLo -ne $actual.IdLo) { throw 'EnrollmentPinsLost' }
                }
            }
            $owner.Observed=Read-VmOwnClock
        }
    } catch {
        $enrollment.Confirmed=$false; $enrollment.Revoked=$true
        if (-not $cleanup) { Set-VmOwnRevoked $owner $_.Exception.Message }
        throw
    } finally { $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false }
}
function Initialize-GbOwnVmGuestEnrollment {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId,[Parameter(Mandatory)][pscredential]$BootstrapCredential)
    $owner=Get-VmOwnRecord $OwnerId
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    if ($owner.Kind -cne 'Windows' -or -not $owner.Storage -or $owner.Storage.Phase -cne 'BootRunning' -or
        -not $owner.Storage.StartSubmitted) { throw 'WindowsOwnBootRequired' }
    if ($owner.GuestEnrollment) { throw 'EnrollmentReplayRejected' }
    $script:VmBoundary.Busy=$true
    try {
        Enter-VmOwnFrame $owner $false; Test-VmOwnFrame; Confirm-VmStoragePeers $owner
        # Reserva antes de paquete, secreto, sesión o mutación guest. No se exporta la hoja.
        $e=@{Owner=$owner;Generation=$owner.Generation;Issuer=$ExecutionContext.SessionState.Module;
            Confirmed=$false;Revoked=$false;Bootstrap=$null;Channel=$null;Package=$null;
            Credential=$null;Secret=$null;BootstrapObservation=$null;AuthenticatedObservation=$null;BootstrapPinsSubmitted=$false;
            Attempts=[Collections.Generic.List[object]]::new();Supervisor=$null;SupervisorModule=$null;
            AccountName=('gb'+$owner.Id.ToString('N').Substring(0,18));AccountSid='';InstallSubmitted=$false;
            DisableSubmitted=$false;DisableObserved=$false;CloseObserved=$false}
        $owner.GuestEnrollment=$e
        $null=Open-VmEnrollmentPackageOwn $owner $e
        $bytes=New-Object byte[] 48; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        $e.Secret=[Security.SecureString]::new()
        try {
            $rng.GetBytes($bytes)
            # Prefijo de complejidad fijo más 384 bits aleatorios; nunca un string de contraseña.
            foreach ($ch in @('G','b','9','!')) { $e.Secret.AppendChar([char]$ch) }
            $alphabet='0123456789abcdef'
            foreach ($byte in $bytes) { $e.Secret.AppendChar($alphabet[$byte -shr 4]); $e.Secret.AppendChar($alphabet[$byte -band 15]) }
            $e.Secret.MakeReadOnly()
        } finally { [Array]::Clear($bytes,0,$bytes.Length); $rng.Dispose() }
        $e.Credential=[pscredential]::new($e.AccountName,$e.Secret); $owner.GuestCredential=$e.Credential
        $null=Open-VmEnrollmentChannelOwn $owner $BootstrapCredential $e 'Bootstrap'
        $BootstrapCredential=$null
        $e.BootstrapObservation=Read-VmEnrollmentBootOwn $owner $e.Bootstrap
        $challenge=New-VmEnrollmentChallengeOwn
        $attempt=Invoke-VmEnrollmentEffectOwn $owner $e $script:VmEnrollmentInstall @(
            $e.Bootstrap.Session,$owner.Id.ToString('N'),$challenge,$e.AccountName,$e.Secret,
            $e.Package.Paths.ToArray(),$e.Package.Hashes.ToArray())
        $reply=$attempt.Outputs[0]
        if ($reply.Owner -cne $owner.Id.ToString('N') -or $reply.Challenge -cne $challenge -or
            $reply.Prepared -isnot [bool] -or -not $reply.Prepared -or $reply.Sid -cnotmatch '^S-1-5-21-[0-9-]+$') { throw 'EnrollmentAccountUnconfirmed' }
        $e.AccountSid=$reply.Sid; $e.Package.Sid=$reply.Sid; $attempt.Confirmed=$true
        for ($i=0;$i -lt 6;$i++) {
            $entry=$e.Package.Entries[$i]; $null=Confirm-VmEnrollmentPackageOwn $owner
            $payload=New-Object byte[] ([int]$entry.Stream.Length)
            try {
                $offset=0; $entry.Stream.Position=0
                while ($offset -lt $payload.Length) {
                    $n=$entry.Stream.Read($payload,$offset,$payload.Length-$offset)
                    if ($n -le 0) { throw 'EnrollmentPackageReadIncomplete' }; $offset+=$n
                }
                $challenge=New-VmEnrollmentChallengeOwn
                $attempt=Invoke-VmEnrollmentEffectOwn $owner $e $script:VmEnrollmentWrite @(
                    $e.Bootstrap.Session,$owner.Id.ToString('N'),$challenge,[int]$i,$payload)
                $reply=$attempt.Outputs[0]
                if ($reply.Owner -cne $owner.Id.ToString('N') -or $reply.Challenge -cne $challenge -or
                    $reply.Index -ne $i -or $reply.Hash -cne $entry.Hash -or $reply.Written -isnot [bool] -or
                    -not $reply.Written) { throw 'EnrollmentPackageWriteUnconfirmed' }
                $attempt.Confirmed=$true
            } finally { [Array]::Clear($payload,0,$payload.Length); $entry.Stream.Position=0 }
        }
        $challenge=New-VmEnrollmentChallengeOwn
        $attempt=Invoke-VmEnrollmentEffectOwn $owner $e $script:VmEnrollmentSeal @(
            $e.Bootstrap.Session,$owner.Id.ToString('N'),$challenge)
        $reply=$attempt.Outputs[0]
        if ($reply.Owner -cne $owner.Id.ToString('N') -or $reply.Challenge -cne $challenge -or
            $reply.Sid -cne $e.AccountSid -or $reply.Sealed -isnot [bool] -or -not $reply.Sealed -or
            @($reply.Files).Count -ne 6) { throw 'EnrollmentPackageSealUnconfirmed' }
        $attempt.Confirmed=$true
        $writtenIdentities=@($reply.Files)
        $challenge=New-VmEnrollmentChallengeOwn; $e.BootstrapPinsSubmitted=$true
        $attempt=Invoke-VmEnrollmentEffectOwn $owner $e $script:VmGuestCall @(
            $e.Bootstrap.Session,'Observe',$owner.Id.ToString('N'),$challenge)
        $reply=$attempt.Outputs[0]
        if ($reply.Owner -cne $owner.Id.ToString('N') -or $reply.Challenge -cne $challenge -or
            $reply.Boot -ne $e.BootstrapObservation.Boot -or $reply.Sid -cne $e.BootstrapObservation.Sid -or
            @($reply.Hashes).Count -ne 6 -or @($reply.Files).Count -ne 6) { throw 'EnrollmentBootstrapPinsUnconfirmed' }
        for ($i=0;$i -lt 6;$i++) {
            if ($reply.Hashes[$i] -cne $e.Package.Hashes[$i] -or $reply.Files[$i].Volume -ne $writtenIdentities[$i].Volume -or
                $reply.Files[$i].IdHi -ne $writtenIdentities[$i].IdHi -or $reply.Files[$i].IdLo -ne $writtenIdentities[$i].IdLo) { throw 'EnrollmentWrittenFileChanged' }
        }
        $e.Package.GuestIdentities=@($reply.Files); $attempt.Confirmed=$true
        $null=Open-VmEnrollmentChannelOwn $owner $e.Credential $e 'Channel'
        $e.AuthenticatedObservation=Read-VmEnrollmentBootOwn $owner $e.Channel
        $left=Read-VmEnrollmentBootOwn $owner $e.Bootstrap
        Confirm-VmEnrollmentBootPairOwn $e.BootstrapObservation $left $true
        Confirm-VmEnrollmentBootPairOwn $left $e.AuthenticatedObservation $false
        if ($e.AuthenticatedObservation.Sid -cne $e.AccountSid) { throw 'EnrollmentAccountChanged' }
        $owner.Observed=Read-VmOwnClock
    } catch {
        if ($owner.GuestEnrollment) { $owner.GuestEnrollment.Revoked=$true; $owner.GuestEnrollment.Confirmed=$false }
        Set-VmOwnRevoked $owner $_.Exception.Message
    } finally { $BootstrapCredential=$null; $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false }
    if (-not $owner.Revoked) {
        # Segundo canal retiene la misma imagen instalada antes de emitir enrollment.
        Invoke-VmGuestObservationOwn $owner
        if (-not $owner.Revoked -and $owner.GuestObservation -and $owner.GuestObservation.Confirmed) {
            $owner.GuestEnrollment.Confirmed=$true; $owner.State='GuestEnrolled'; $owner.Cause='BrokerNoJobNotObserved'
        }
    }
    Get-VmOwnView $owner
}

function Open-GbOwnVmCapture {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId,
        [Parameter(Mandatory)][string]$CaptureLocal,[Parameter(Mandatory)][string]$CapturePeer)
    $owner=Get-VmOwnRecord $OwnerId; $e=$owner.GuestEnrollment
    if (-not $e) { throw 'EnrollmentRequired' }
    Confirm-VmGuestEnrollmentOwn $e
    if ($e.Supervisor) { throw 'CaptureSupervisorReplay' }
    # El módulo recibe la referencia viva exacta, no VMId/hash/SID equivalentes.
    $modulePath=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\GuestSupervisor.psm1'))
    $modules=@(Get-Module | Where-Object Path -CEQ $modulePath)
    if ($modules.Count -eq 0) { $modules=@(Import-Module -Name $modulePath -PassThru -ErrorAction Stop) }
    if ($modules.Count -ne 1) { throw 'CaptureSupervisorModuleCardinality' }
    $e.SupervisorModule=$modules[0]
    & $e.SupervisorModule { param($bound,$local,$peer)
        Open-GbOwnEnrollmentSupervisor $bound $local $peer
    } $e $CaptureLocal $CapturePeer
}
$script:VmEnrollmentDisable={
    param($session,$ownerId,$challenge,$sid,$boot)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($ownerId,$challenge,$sid,$boot)
        $a=$global:GbVmEnrollmentAttempt
        if (-not $a -or $a.Owner -cne $ownerId -or $challenge -cnotmatch '^[0-9a-f]{64}$' -or
            -not $a.Account -or $a.Sid -cne $sid -or $a.Account.SID.Value -cne $sid -or
            (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().Ticks -ne $boot) { throw 'EnrollmentDisableIdentityUnknown' }
        # Deshabilitar la cuenta exacta original; no borrar/adoptar un homónimo.
        $matches=@(Get-LocalUser -SID $a.Account.SID -ErrorAction Stop)
        if ($matches.Count -ne 1 -or $matches[0].SID.Value -cne $sid -or $matches[0].Name -cne $a.Name) { throw 'EnrollmentAccountChanged' }
        $a.DisableSubmitted=$true
        Disable-LocalUser -InputObject $a.Account -ErrorAction Stop
        $matches=@(Get-LocalUser -SID $a.Account.SID -ErrorAction Stop)
        if ($matches.Count -ne 1 -or $matches[0].Enabled -or $matches[0].Name -cne $a.Name) { throw 'EnrollmentDisableUnconfirmed' }
        $a.Disabled=$true
        # Archivos/cuenta quedan conservados; se cierran sólo hojas propias adquiridas.
        foreach ($slot in $a.Writes) { if ($slot.Stream) { $slot.Stream.Dispose(); $slot.Stream=$null } }
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Sid=$sid;Disabled=$true}
    } -ArgumentList $ownerId,$challenge,$sid,$boot -ErrorAction Stop
}
function Close-VmGuestEnrollmentOwn($owner) {
    $e=$owner.GuestEnrollment
    if (-not $e -or $e.CloseObserved) { return }
    $e.Confirmed=$false; $e.Revoked=$true
    if (-not [object]::ReferenceEquals((Get-VmOwnRecord $owner.Id),$owner) -or
        -not [object]::ReferenceEquals($e.Owner,$owner)) { throw 'EnrollmentOwnerUnknown' }
    if ($e.Supervisor) {
        & $e.SupervisorModule { param($bound) Close-GbOwnEnrollmentSupervisor $bound } $e | Out-Null
        if ($e.Supervisor.State -cne 'Closed') { throw 'EnrollmentCaptureClosePending' }
    }
    if ($owner.GuestObservation) { Close-VmGuestObservationOwn $owner }
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    $script:VmBoundary.Busy=$true
    try {
        Enter-VmOwnFrame $owner $true; Test-VmOwnFrame; Confirm-VmStoragePeers $owner
        if ($e.InstallSubmitted -and -not $e.DisableObserved) {
            Confirm-VmEnrollmentChannelOwn $owner $e.Bootstrap $true
            if (-not $e.AccountSid -or -not $e.BootstrapObservation) { throw 'EnrollmentAccountEffectUncertain' }
            # Una respuesta incierta no habilita volver a emitir Disable.
            if ($e.DisableSubmitted) { throw 'EnrollmentDisableEffectUncertain' }
            $challenge=New-VmEnrollmentChallengeOwn; $e.DisableSubmitted=$true
            $disableArguments=@($e.Bootstrap.Session,$owner.Id.ToString('N'),$challenge,$e.AccountSid,$e.BootstrapObservation.Boot)
            $reply=@(& $script:VmEnrollmentDisable @disableArguments)
            Test-VmOwnFrame; Confirm-VmEnrollmentChannelOwn $owner $e.Bootstrap $true
            if ($reply.Count -ne 1 -or $reply[0].Owner -cne $owner.Id.ToString('N') -or
                $reply[0].Challenge -cne $challenge -or $reply[0].Sid -cne $e.AccountSid -or
                $reply[0].Disabled -isnot [bool] -or -not $reply[0].Disabled) { throw 'EnrollmentDisableUnconfirmed' }
            $e.DisableObserved=$true
        }
        if ($e.BootstrapPinsSubmitted) {
            Confirm-VmEnrollmentChannelOwn $owner $e.Bootstrap $true
            $challenge=New-VmEnrollmentChallengeOwn
            $reply=@(& $script:VmGuestCall $e.Bootstrap.Session 'Close' $owner.Id.ToString('N') $challenge)
            Test-VmOwnFrame; Confirm-VmEnrollmentChannelOwn $owner $e.Bootstrap $true
            if ($reply.Count -ne 1 -or $reply[0].Owner -cne $owner.Id.ToString('N') -or
                $reply[0].Challenge -cne $challenge -or $reply[0].Closed -isnot [bool] -or
                -not $reply[0].Closed) { throw 'EnrollmentBootstrapPinsCloseUnconfirmed' }
            $e.BootstrapPinsSubmitted=$false
        }
        foreach ($channel in @($e.Channel,$e.Bootstrap)) {
            if (-not $channel -or $channel.Closed) { continue }
            foreach ($session in @($channel.Resources)) {
                if ($session -isnot [System.Management.Automation.Runspaces.PSSession] -or
                    $session.Runspace.ConnectionInfo -isnot [System.Management.Automation.Runspaces.VMConnectionInfo] -or
                    $session.Runspace.ConnectionInfo.VMGuid -ne $owner.VmId) { throw 'EnrollmentCleanupIdentityUnknown' }
                & $script:VmGuestRemove $session
                $null=$channel.Resources.Remove($session)
            }
            $channel.Session=$null; $channel.Closed=$true
        }
        if ($e.Package) {
            foreach ($entry in $e.Package.Entries) {
                if ($entry.Stream) { $entry.Stream.Dispose(); $entry.Stream=$null }
                foreach ($handle in $entry.Parents) { $handle.Dispose() }
                $entry.Parents.Clear()
            }
            $e.Package.Complete=$false
        }
        if ($e.Secret) { $e.Secret.Dispose(); $e.Secret=$null }
        $e.Credential=$null; $owner.GuestCredential=$null; $e.CloseObserved=$true
    } finally { $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false }
}
