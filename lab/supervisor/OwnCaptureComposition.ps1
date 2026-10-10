function Initialize-GbSupervisorCustodyOwn {
    if ('GbSupervisorCustody' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class GbSupervisorCustody {
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

}
'@ -ErrorAction Stop
}
# Composición de captura del supervisor: el paquete se adquiere por rutas propias fijas.
function Open-GbCapturePackageOwn($owner) {
    Initialize-GbSupervisorCustodyOwn
    if ($owner.CapturePackage) { return $owner.CapturePackage }
    if ($owner.Enrollment) {
        Confirm-GbEnrollmentOwn $owner
        $source=$owner.Enrollment.Package
        $package=@{Owner=$owner;Generation=$owner.Generation;Streams=[Collections.Generic.List[object]]::new();
            Hashes=@{};Module=$null;Complete=$false;Parents=[Collections.Generic.List[object]]::new();
            ParentPaths=[Collections.Generic.List[string]]::new();Paths=[Collections.Generic.List[string]]::new();
            Identities=[Collections.Generic.List[object]]::new();BorrowedEnrollment=$owner.Enrollment}
        $owner.CapturePackage=$package
        $names=@('ModuleHash','LauncherHash','ConverterHash')
        for ($i=0;$i -lt 3;$i++) {
            $entry=$source.Entries[$i+3]
            # Misma hoja host que escribió y fijó el paquete guest; no reabrir por DTO/hash.
            $package.Streams.Add($entry.Stream); $package.Paths.Add($entry.Path)
            $package.Identities.Add([GbSupervisorCustody]::Inspect($entry.Stream.SafeFileHandle,$entry.Path,$false))
            $package.Hashes[$names[$i]]=$entry.Hash
        }
        $path=$package.Paths[0]
        $modules=@(Get-Module | Where-Object Path -CEQ $path)
        if ($modules.Count -eq 0) { $modules=@(Import-Module -Name $path -PassThru -ErrorAction Stop) }
        if ($modules.Count -ne 1) { throw 'CaptureModuleCardinality' }
        $package.Module=$modules[0]
        Confirm-GbEnrollmentOwn $owner
        $package.Complete=$true
        return $package
    }
    $package=@{Owner=$owner;Generation=$owner.Generation;Streams=[Collections.Generic.List[object]]::new();
        Hashes=@{};Module=$null;Complete=$false;Parents=[Collections.Generic.List[object]]::new();
        ParentPaths=[Collections.Generic.List[string]]::new();Paths=[Collections.Generic.List[string]]::new();Identities=[Collections.Generic.List[object]]::new()}
    $owner.CapturePackage=$package
    $paths=@{ModuleHash=(Join-Path $PSScriptRoot 'capture\capture_netevent.psm1');
        LauncherHash=(Join-Path $PSScriptRoot '..\bin\guest_conversion.dll');
        ConverterHash=(Join-Path $PSScriptRoot '..\bin\conversion_worker.exe')}
    foreach ($name in @('ModuleHash','LauncherHash','ConverterHash')) {
        Test-GbCurrent $owner $owner.Generation
        $path=[IO.Path]::GetFullPath($paths[$name])
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $package.Streams.Add($stream)
        $package.Paths.Add($path)
        $identity=[GbSupervisorCustody]::Inspect($stream.SafeFileHandle,$path,$false)
        $package.Identities.Add($identity)
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $stream.Length -le 0 -or $stream.Length -gt 16777216) { throw 'CapturePackageInvalid' }
        $parent=[IO.Path]::GetDirectoryName($path)
        while ($parent) {
            $handle=[GbSupervisorCustody]::Parent($parent)
            $package.Parents.Add($handle); $package.ParentPaths.Add($parent)
            $null=[GbSupervisorCustody]::Inspect($handle,$parent,$true)
            $entry=Get-Item -LiteralPath $parent -ErrorAction Stop
            if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'CapturePackageParentInvalid' }
            $parent=[IO.Path]::GetDirectoryName($parent.TrimEnd('\'))
        }
        $sha=[Security.Cryptography.SHA256]::Create()
        try { $package.Hashes[$name]=([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','') }
        finally { $sha.Dispose(); $stream.Position=0 }
        if (-not [GbSupervisorCustody]::Same($identity,[GbSupervisorCustody]::Inspect($stream.SafeFileHandle,$path,$false))) { throw 'CapturePackageChanged' }
        Test-GbCurrent $owner $owner.Generation
    }
    $modules=@(Get-Module | Where-Object Path -CEQ ([IO.Path]::GetFullPath($paths.ModuleHash)))
    if ($modules.Count -eq 0) { $modules=@(Import-Module -Name $paths.ModuleHash -PassThru -ErrorAction Stop) }
    if ($modules.Count -ne 1) { throw 'CaptureModuleCardinality' }
    $package.Module=$modules[0]; $package.Complete=$true
    return $package
}
function Confirm-GbCapturePackageOwn($owner) {
    $package=$owner.CapturePackage
    if (-not $package -or -not $package.Complete -or -not [object]::ReferenceEquals($package.Owner,$owner) -or
        $package.Generation -ne $owner.Generation -or $package.Streams.Count -ne 3 -or -not $package.Module) { throw 'CapturePackageRevoked' }
    if ($owner.Enrollment) {
        if (-not [object]::ReferenceEquals($package.BorrowedEnrollment,$owner.Enrollment)) { throw 'CapturePackageRevoked' }
        Confirm-GbEnrollmentOwn $owner
    }
    for ($i=0;$i -lt $package.Streams.Count;$i++) {
        if (-not $package.Streams[$i].CanRead -or -not [GbSupervisorCustody]::Same($package.Identities[$i],
            [GbSupervisorCustody]::Inspect($package.Streams[$i].SafeFileHandle,$package.Paths[$i],$false))) { throw 'CapturePackageLost' }
    }
    for ($i=0;$i -lt $package.Parents.Count;$i++) { $null=[GbSupervisorCustody]::Inspect($package.Parents[$i],$package.ParentPaths[$i],$true) }
    return $package
}
$script:GbCaptureProfileRead = {
    param($session,$index)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($index)
        $nic=Get-NetAdapter -InterfaceIndex $index -ErrorAction Stop
        $ips=@(Get-NetIPAddress -InterfaceIndex $index -ErrorAction Stop | ForEach-Object IPAddress)
        $inbox='C:\Windows\System32\WindowsPowerShell\v1.0\Modules\NetEventPacketCapture\NetEventPacketCapture.psd1'
        [pscustomobject]@{BootTime=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime.ToUniversalTime().ToString('o');
            GuestUserSID=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;InterfaceGuid=[guid]$nic.InterfaceGuid;
            Index=[uint32]$nic.ifIndex;Name=[string]$nic.Name;MAC=[string]$nic.MacAddress;MTU=[int]$nic.MtuSize;IPs=$ips;
            InboxModuleHash=(Get-FileHash -LiteralPath $inbox -Algorithm SHA256 -ErrorAction Stop).Hash;
            InboxModuleVersion=(Test-ModuleManifest -Path $inbox -ErrorAction Stop).Version.ToString()}
    } -ArgumentList $index -ErrorAction Stop
}
$script:GbComposition=@{
    Current={
        param($owner,$run,$generation)
        Test-GbCurrent $owner $generation
        Confirm-GbEnrollmentOwn $owner
        if (-not [object]::ReferenceEquals((Get-GbOwner $owner.Id),$owner) -or $run -eq [guid]::Empty) { throw 'CaptureOwnerUnknown' }
        if ($owner.Gate) {
            $null=Confirm-GbCapturePackageOwn $owner
            if ($owner.Run -ne $run) { throw 'CaptureRunChanged' }
            return $owner.Gate
        }
        $package=Open-GbCapturePackageOwn $owner
        $reply=@(& $script:GbCaptureProfileRead $owner.Session $owner.Nic.Index)
        Test-GbCurrent $owner $generation
        $null=Confirm-GbCapturePackageOwn $owner
        if ($reply.Count -ne 1) { throw 'CaptureProfileCardinality' }
        $reply=$reply[0]
        if ([DateTime]::Parse($reply.BootTime).ToUniversalTime().Ticks -ne $owner.Boot -or
            $reply.GuestUserSID -cne $owner.Plan.Sid -or $reply.InterfaceGuid -ne $owner.Nic.Guid -or
            $reply.Index -ne $owner.Nic.Index -or $reply.Name -cne $owner.Nic.Name -or
            ($reply.MAC -replace '[-:]','').ToUpperInvariant() -cne $owner.Plan.Mac -or
            $reply.MTU -le 0 -or $reply.MTU -gt 1500 -or -not(@($reply.IPs) -ccontains $owner.CaptureLocal)) { throw 'CaptureGuestChanged' }
        $profile=@{BootTime=$reply.BootTime;GuestUserSID=$reply.GuestUserSID;InterfaceGuid=$reply.InterfaceGuid;
            Index=$reply.Index;Name=$reply.Name;MAC=$reply.MAC;MTU=$reply.MTU;Local=$owner.CaptureLocal;Peer=$owner.CapturePeer;
            ModuleHash=$package.Hashes.ModuleHash;LauncherHash=$package.Hashes.LauncherHash;ConverterHash=$package.Hashes.ConverterHash;
            InboxModuleHash=$reply.InboxModuleHash;InboxModuleVersion=$reply.InboxModuleVersion;
            ManifestHashes=@($package.Hashes.ModuleHash,$package.Hashes.LauncherHash,$package.Hashes.ConverterHash)}
        $owner.Run=$run
        $owner.Gate=& $package.Module { param($session,$vm,$run,$profile,$token)
            New-GBCaptureGate $session $vm $run $profile $token
        } $owner.Session $owner.VmId $run $profile $owner.CaptureCancel.Token
        Test-GbCurrent $owner $generation
        if (-not $owner.Gate -or $owner.Gate.State -cne 'Challenged') { throw 'CaptureChallengeIncomplete' }
        return $owner.Gate
    }
    Step={
        param($gate,$step)
        $owners=@($script:GbOwners.Values | Where-Object { [object]::ReferenceEquals($_.Gate,$gate) })
        if ($owners.Count -ne 1) { throw 'CaptureGateUnknown' }
        $owner=$owners[0]
        Confirm-GbEnrollmentOwn $owner ($step -in @('Stop','Cleanup','Cancel'))
        $package=$owner.CapturePackage
        if (-not $package -or -not [object]::ReferenceEquals($package.Owner,$owner) -or -not $package.Module) { throw 'CapturePackageUnknown' }
        Test-GbCurrent $owner $owner.Generation ($step -in @('Stop','Cleanup','Cancel'))
        & $package.Module { param($gate,$step) Invoke-GBCaptureStep $gate $step } $gate $step
    }
}
