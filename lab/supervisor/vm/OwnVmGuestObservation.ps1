# Observacion Windows por el mismo owner; no emite enrolamiento Linux ni NoJob.
$script:VmGuestCreate={ param($vm,$credential) Microsoft.PowerShell.Core\New-PSSession -VMId $vm -Credential $credential -ErrorAction Stop }
$script:VmGuestRemove={ param($session) Microsoft.PowerShell.Core\Remove-PSSession -Session $session -ErrorAction Stop }
$script:VmGuestCall={
    param($session,$operation,$ownerId,$challenge)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($operation,$ownerId,$challenge)
        if ($ownerId -cnotmatch '^[0-9a-f]{32}$' -or $challenge -cnotmatch '^[0-9a-f]{64}$') { throw 'GuestRequestInvalid' }
        if (-not (Get-Variable -Name GbGuestOwnObservation -Scope Global -ErrorAction SilentlyContinue)) {
            $global:GbGuestOwnObservation=$null
        }
        if ($operation -ceq 'Close') {
            $item=$global:GbGuestOwnObservation
            if (-not $item -or $item.Owner -cne $ownerId) { throw 'GuestCustodyUnknown' }
            foreach ($stream in $item.Streams) { $stream.Dispose() }
            foreach ($handle in $item.Parents) { $handle.Dispose() }
            $global:GbGuestOwnObservation=$null
            return [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Closed=$true}
        }
        if ($operation -cne 'Observe') { throw 'GuestOperationInvalid' }
        if (-not ('GbGuestReadCustody' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class GbGuestReadCustody {
 [StructLayout(LayoutKind.Sequential)] public struct Info {
  public uint Attr, CreateLo, CreateHi, AccessLo, AccessHi, WriteLo, WriteHi, Volume, SizeHi, SizeLo, Links, IdHi, IdLo;
 }
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr sa,uint d,uint f,IntPtr t);
 [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info i);
 [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder b,uint n,uint f);
 public static Info Inspect(SafeFileHandle h,string p,bool dir) {
  Info i; var b=new StringBuilder(1024); uint n=GetFinalPathNameByHandleW(h,b,1024,0);
  if(h.IsClosed||h.IsInvalid||!GetFileInformationByHandle(h,out i)||n==0||n>=1024||
     b.ToString()!=@"\\?\"+p||(i.Attr&0x400)!=0||((i.Attr&0x10)!=0)!=dir||(!dir&&i.Links!=1)) throw new InvalidOperationException("GuestFileIdentityUnknown");
  return i;
 }
 public static SafeFileHandle Parent(string p) { return CreateFileW(p,0x80,3,IntPtr.Zero,3,0x02200000,IntPtr.Zero); }
 public static bool Same(Info a,Info b) { return a.Volume==b.Volume&&a.IdHi==b.IdHi&&a.IdLo==b.IdLo&&a.SizeHi==b.SizeHi&&a.SizeLo==b.SizeLo&&a.WriteHi==b.WriteHi&&a.WriteLo==b.WriteLo; }
}
'@ -ErrorAction Stop
        }
        if (-not $global:GbGuestOwnObservation) {
            # Reserva antes del primer archivo; error parcial conserva todos los streams adquiridos.
            $global:GbGuestOwnObservation=@{Owner=$ownerId;Streams=[Collections.Generic.List[object]]::new();
                Parents=[Collections.Generic.List[object]]::new();ParentPaths=[Collections.Generic.List[string]]::new();
                Identities=[Collections.Generic.List[object]]::new();Complete=$false}
            foreach ($path in @('C:\GateBouncerLab\bin\guest_broker.exe','C:\GateBouncerLab\supervisor\GuestCommands.ps1')) {
                $stream=[IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
                $global:GbGuestOwnObservation.Streams.Add($stream)
                $global:GbGuestOwnObservation.Identities.Add([GbGuestReadCustody]::Inspect($stream.SafeFileHandle,$path,$false))
                $parent=[IO.Path]::GetDirectoryName($path)
                while ($parent) {
                    $handle=[GbGuestReadCustody]::Parent($parent)
                    $global:GbGuestOwnObservation.Parents.Add($handle)
                    $global:GbGuestOwnObservation.ParentPaths.Add($parent)
                    $null=[GbGuestReadCustody]::Inspect($handle,$parent,$true)
                    $parent=[IO.Path]::GetDirectoryName($parent.TrimEnd('\'))
                }
                $entry=Get-Item -LiteralPath $path -ErrorAction Stop
                if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'GuestImageInvalid' }
            }
            $global:GbGuestOwnObservation.Complete=$true
        }
        $item=$global:GbGuestOwnObservation
        if ($item.Owner -cne $ownerId -or -not $item.Complete -or $item.Streams.Count -ne 2) { throw 'GuestCustodyUnknown' }
        $hashes=[Collections.Generic.List[string]]::new()
        for ($i=0;$i -lt $item.Parents.Count;$i++) { $null=[GbGuestReadCustody]::Inspect($item.Parents[$i],$item.ParentPaths[$i],$true) }
        for ($i=0;$i -lt $item.Streams.Count;$i++) {
            $stream=$item.Streams[$i]
            if (-not $stream.CanRead -or $stream.Length -le 0 -or $stream.Length -gt 16777216) { throw 'GuestImageInvalid' }
            if (-not [GbGuestReadCustody]::Same($item.Identities[$i],[GbGuestReadCustody]::Inspect($stream.SafeFileHandle,$stream.Name,$false))) { throw 'GuestImageChanged' }
            $stream.Position=0; $sha=[Security.Cryptography.SHA256]::Create()
            try { $hashes.Add(([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','')) }
            finally { $sha.Dispose() }
            $stream.Position=0
            if (-not [GbGuestReadCustody]::Same($item.Identities[$i],[GbGuestReadCustody]::Inspect($stream.SafeFileHandle,$stream.Name,$false))) { throw 'GuestImageChanged' }
        }
        $boot=Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $nics=@(Get-NetAdapter -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{Guid=[guid]$_.InterfaceGuid;Index=[int]$_.ifIndex;
                Mac=([string]$_.MacAddress -replace '[-:]','').ToUpperInvariant()}
        })
        if ($nics.Count -gt 16) { throw 'GuestTopologyBudget' }
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Boot=[long]$boot.LastBootUpTime.ToUniversalTime().Ticks;
            Sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Hashes=$hashes.ToArray();Nics=$nics}
    } -ArgumentList $operation,$ownerId,$challenge -ErrorAction Stop
}
function Confirm-VmGuestSessionOwn($owner) {
    $guest=$owner.GuestObservation
    if (-not $guest -or -not $guest.Session -or $guest.Session -isnot [System.Management.Automation.Runspaces.PSSession]) { throw 'GuestSessionMissing' }
    $connection=$guest.Session.Runspace.ConnectionInfo
    if ($connection -isnot [System.Management.Automation.Runspaces.VMConnectionInfo] -or $connection.VMGuid -ne $owner.VmId -or
        $guest.Session.InstanceId -ne $guest.Instance -or [string]$guest.Session.Runspace.RunspaceStateInfo.State -cne 'Opened' -or
        [string]$guest.Session.Availability -cne 'Available') { throw 'GuestSessionChanged' }
}
function Invoke-VmGuestObservationOwn($owner) {
    if (-not [object]::ReferenceEquals((Get-VmOwnRecord $owner.Id),$owner)) { throw 'GuestOwnerUnknown' }
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    # Paquete y credencial solo pueden venir del productor propio futuro; no existen setters/export.
    if (-not $owner.GuestPackage -or -not [object]::ReferenceEquals($owner.GuestPackage.Owner,$owner) -or
        $owner.GuestPackage.Generation -ne $owner.Generation -or $owner.GuestPackage.Hashes.Count -ne 2 -or
        $owner.Kind -cne 'Windows') { throw 'GuestPackageNotBound' }
    $script:VmBoundary.Busy=$true
    try {
        Enter-VmOwnFrame $owner $false; Test-VmOwnFrame; Confirm-VmStoragePeers $owner
        if (-not $owner.GuestObservation) {
            if ($owner.GuestCredential -isnot [pscredential]) { throw 'GuestCredentialNotBound' }
            $guest=@{Owner=$owner;Generation=$owner.Generation;Session=$null;Instance=[guid]::Empty;
                Resources=[Collections.Generic.List[object]]::new();Boot=[long]0;Nic=$null;Confirmed=$false;Package=$owner.GuestPackage;
                ObserveSubmitted=$false;Observed=[long]0}
            $owner.GuestObservation=$guest
            & $script:VmGuestCreate $owner.VmId $owner.GuestCredential | ForEach-Object {
                $guest.Resources.Add($_); $guest.Session=$_
            }
            Test-VmOwnFrame
            if ($guest.Resources.Count -ne 1 -or $guest.Session -isnot [System.Management.Automation.Runspaces.PSSession]) { throw 'GuestSessionCardinality' }
            $guest.Instance=[guid]$guest.Session.InstanceId
        }
        $guest=$owner.GuestObservation; $guest.Confirmed=$false
        if (-not [object]::ReferenceEquals($guest.Owner,$owner) -or $guest.Generation -ne $owner.Generation -or
            -not [object]::ReferenceEquals($guest.Package,$owner.GuestPackage)) { throw 'GuestPackageChanged' }
        Confirm-VmGuestSessionOwn $owner
        $random=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($random) } finally { $rng.Dispose() }
        $challenge=([BitConverter]::ToString($random) -replace '-','').ToLowerInvariant()
        $guest.ObserveSubmitted=$true
        $reply=@(& $script:VmGuestCall $guest.Session 'Observe' $owner.Id.ToString('N') $challenge)
        Test-VmOwnFrame; Confirm-VmStoragePeers $owner; Confirm-VmGuestSessionOwn $owner
        if ($reply.Count -ne 1) { throw 'GuestReplyCardinality' }
        $reply=$reply[0]
        if ($reply.Owner -cne $owner.Id.ToString('N') -or $reply.Challenge -cne $challenge -or
            $reply.Boot -isnot [long] -or $reply.Boot -le 0 -or ($guest.Boot -and $guest.Boot -ne $reply.Boot) -or
            $reply.Sid -cne $guest.Package.Sid -or @($reply.Hashes).Count -ne 2) { throw 'GuestBootPinChanged' }
        for ($i=0;$i -lt 2;$i++) {
            if ($guest.Package.Hashes[$i] -cnotmatch '^[0-9A-F]{64}$' -or $reply.Hashes[$i] -cne $guest.Package.Hashes[$i]) { throw 'GuestImagePinChanged' }
        }
        $adapters=@(Read-VmOwnPort $script:VmAdapters @($owner.Resources[0].Ref))
        if ($adapters.Count -ne 1) { throw 'GuestTopologyChanged' }
        $mac=([string]$adapters[0].MacAddress -replace '[-:]','').ToUpperInvariant()
        $nics=@($reply.Nics | Where-Object { $_.Mac -ceq $mac })
        if (@($reply.Nics).Count -gt 16 -or $nics.Count -ne 1 -or [guid]$nics[0].Guid -eq [guid]::Empty -or [int]$nics[0].Index -le 0) { throw 'GuestTopologyChanged' }
        if ($guest.Nic -and ($guest.Nic.Guid -ne $nics[0].Guid -or $guest.Nic.Index -ne $nics[0].Index)) { throw 'GuestTopologyChanged' }
        Confirm-VmStoragePeers $owner; Test-VmOwnFrame
        $guest.Boot=[long]$reply.Boot; $guest.Nic=$nics[0]; $guest.Confirmed=$true
        $owner.Observed=Read-VmOwnClock
        $guest.Observed=$owner.Observed
    } catch {
        if ($owner.GuestObservation) { $owner.GuestObservation.Confirmed=$false }
        Set-VmOwnRevoked $owner $_.Exception.Message
    } finally { $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false }
}
function Close-VmGuestObservationOwn($owner) {
    if (-not [object]::ReferenceEquals((Get-VmOwnRecord $owner.Id),$owner)) { throw 'GuestOwnerUnknown' }
    $guest=$owner.GuestObservation
    if (-not $guest) { return }
    $guest.Confirmed=$false
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    $script:VmBoundary.Busy=$true
    try {
    if (-not $guest.ObserveSubmitted) {
        foreach ($session in @($guest.Resources)) {
            if ($session -isnot [System.Management.Automation.Runspaces.PSSession] -or
                $session.Runspace.ConnectionInfo -isnot [System.Management.Automation.Runspaces.VMConnectionInfo] -or
                $session.Runspace.ConnectionInfo.VMGuid -ne $owner.VmId) { throw 'GuestCleanupIdentityUnknown' }
            & $script:VmGuestRemove $session
            $null=$guest.Resources.Remove($session)
        }
        $owner.GuestObservation=$null
        return
    }
    # Canal perdido conserva cuarentena: no crea otro para fabricar disposicion de streams.
    Confirm-VmGuestSessionOwn $owner
    $bytes=New-Object byte[] 32; $rng=[Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    $challenge=([BitConverter]::ToString($bytes) -replace '-','').ToLowerInvariant()
    $reply=@(& $script:VmGuestCall $guest.Session 'Close' $owner.Id.ToString('N') $challenge)
    Confirm-VmGuestSessionOwn $owner
    if ($reply.Count -ne 1 -or $reply[0].Closed -isnot [bool] -or -not $reply[0].Closed -or
        $reply[0].Owner -cne $owner.Id.ToString('N') -or $reply[0].Challenge -cne $challenge) { throw 'GuestCloseUnconfirmed' }
    & $script:VmGuestRemove $guest.Session
    $guest.Session=$null; $guest.Resources.Clear(); $owner.GuestObservation=$null
    } finally { $script:VmBoundary.Busy=$false }
}
