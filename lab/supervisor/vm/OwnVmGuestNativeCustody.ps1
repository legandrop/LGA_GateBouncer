# Custodia guest: tipo propio retenido en el runspace original, sin secretos serializados.
$script:VmNativeLoad={
    param($session,$ownerId,$challenge,$role)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($ownerId,$challenge,$role)
        if($ownerId -cnotmatch '^[0-9a-f]{32}$' -or $challenge -cnotmatch '^[0-9a-f]{64}$' -or
           $role -cnotin @('Bootstrap','Controller')) { throw 'NativeRequestInvalid' }
        if(Get-Variable -Name GbGuestNativeCustody -Scope Global -ErrorAction SilentlyContinue) { throw 'NativeCustodyReplay' }
        $record=$global:GbGuestOwnObservation
        if(-not $record -or $record.Owner -cne $ownerId -or -not $record.Complete -or $record.Streams.Count -ne 7) {
            throw 'NativeOriginalReadersRequired'
        }
        if(-not ('GbGuestNativeCustody' -as [type])) {
            Add-Type -ReferencedAssemblies @([System.Management.Automation.PSObject].Assembly.Location,'System.dll','System.Core.dll') -TypeDefinition @'
using System;
using System.IO;
using System.Collections.Generic;
using System.Collections;
using System.Security.Principal;
using System.Management.Automation;
using System.Runtime.InteropServices;
using System.Threading;
using System.Management.Automation.Runspaces;
public sealed class GbGuestNativeCustody {
 const string Library=@"C:\GateBouncerLab\bin\guest_native_controller.dll";
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl,CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbBootstrapReserveOwn(IntPtr[] files,byte[] pins,IntPtr stop,string name,out IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbBootstrapStartOwn(IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbBootstrapReadyOwn(IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl,CharSet=CharSet.Unicode)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbBootstrapAccountOwn(IntPtr leaf,string sid);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbBootstrapBeginAccountOwn(IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbControllerReserveOwn(IntPtr[] files,byte[] pins,IntPtr stop,out IntPtr leaf,out uint pid,out ulong made,out ulong cookie);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbBootstrapBindOwn(IntPtr leaf,uint pid,ulong made,ulong cookie);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbControllerBindOwn(IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbBootstrapSealOwn(IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbNativeCurrentOwn(IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbNativeRevokeOwn(IntPtr leaf);
 [DllImport(Library,CallingConvention=CallingConvention.Cdecl)] [return:MarshalAs(UnmanagedType.I1)]
 static extern bool GbNativeCloseOwn(IntPtr leaf);
 static readonly Dictionary<Runspace,GbGuestNativeCustody> Retained=new Dictionary<Runspace,GbGuestNativeCustody>();
 readonly Runspace runspace;
 readonly FileStream[] files;
 readonly EventWaitHandle stop=new EventWaitHandle(false,EventResetMode.ManualReset);
 readonly bool bootstrap;
 readonly IDictionary attempt;
 readonly string accountName;
 object originalAccount;
 bool accountBeginning;
 public string Owner {get;private set;}
 IntPtr leaf=IntPtr.Zero;
 bool revoked,closed,submitted;
 public uint Pid {get;private set;}
 public ulong Creation {get;private set;}
 public ulong Correlation {get;private set;}
 GbGuestNativeCustody(FileStream[] originals,bool keeper,string owner,IDictionary stage) {
  runspace=Runspace.DefaultRunspace; files=originals; bootstrap=keeper;
  Owner=owner;attempt=stage;accountName="gb"+owner.Substring(0,18);
  if(runspace==null) throw new InvalidOperationException("NativeRunspaceRequired");
  if(keeper) {
   if(stage==null||(string)stage["Owner"]!=owner||(string)stage["Name"]!=accountName||!(bool)stage["Complete"])
    throw new InvalidOperationException("NativeOriginalAttemptRequired");
   var slots=stage["Writes"] as IList;
   if(slots==null||slots.Count!=7) throw new InvalidOperationException("NativeOriginalAttemptRequired");
   for(int i=0;i<7;i++) if(!Object.ReferenceEquals(PSObject.AsPSObject(((IDictionary)slots[i])["Stream"]).BaseObject,originals[i]))
    throw new InvalidOperationException("NativeOriginalAttemptRequired");
  }
  runspace.StateChanged+=StateChangedOwn;
 }
 void StateChangedOwn(object sender,RunspaceStateEventArgs e) {
  if(e.RunspaceStateInfo.State!=RunspaceState.Opened) RevokeOwn();
 }
 void GuardOwn() {
  if(revoked||closed||!Object.ReferenceEquals(Runspace.DefaultRunspace,runspace)||
     runspace.RunspaceStateInfo.State!=RunspaceState.Opened) throw new InvalidOperationException("NativeOriginalRunspaceRequired");
  foreach(var file in files) if(file==null||!file.CanRead||file.SafeFileHandle.IsClosed) throw new InvalidOperationException("NativeReaderLost");
 }
 public static GbGuestNativeCustody ReserveOwn(FileStream[] originalReaders,byte[] hashes,bool keeper,string owner,IDictionary stage) {
  if(originalReaders==null||originalReaders.Length!=7||hashes==null||hashes.Length!=224||owner==null||owner.Length!=32)
   throw new InvalidOperationException("NativePackageInvalid");
  var record=new GbGuestNativeCustody(originalReaders,keeper,owner,stage);
  lock(Retained) {
   if(Retained.ContainsKey(record.runspace)) {
    record.runspace.StateChanged-=record.StateChangedOwn;record.stop.Dispose();
    throw new InvalidOperationException("NativeReserveReplay");
   }
   Retained.Add(record.runspace,record);
  }
  record.GuardOwn();
  bool[] borrowed=new bool[7]; bool eventBorrowed=false;
  IntPtr[] handles=new IntPtr[7];
  try {
   for(int i=0;i<7;i++) {
    originalReaders[i].SafeFileHandle.DangerousAddRef(ref borrowed[i]);
    handles[i]=originalReaders[i].SafeFileHandle.DangerousGetHandle();
   }
   record.stop.SafeWaitHandle.DangerousAddRef(ref eventBorrowed);
   record.submitted=true; bool ok;
   if(keeper) ok=GbBootstrapReserveOwn(handles,hashes,record.stop.SafeWaitHandle.DangerousGetHandle(),record.accountName,out record.leaf);
   else {
    uint pid; ulong made,cookie;
    ok=GbControllerReserveOwn(handles,hashes,record.stop.SafeWaitHandle.DangerousGetHandle(),out record.leaf,out pid,out made,out cookie);
    record.Pid=pid; record.Creation=made; record.Correlation=cookie;
   }
   if(!ok) throw new InvalidOperationException("NativeReserveUnconfirmed");
   return record;
  } catch { record.RevokeOwn(); throw; }
  finally {
   for(int i=0;i<7;i++) if(borrowed[i]) originalReaders[i].SafeFileHandle.DangerousRelease();
   if(eventBorrowed) record.stop.SafeWaitHandle.DangerousRelease();
  }
 }
 public static GbGuestNativeCustody OriginalOwn() {
  lock(Retained) {
   GbGuestNativeCustody record;
   return Runspace.DefaultRunspace!=null&&Retained.TryGetValue(Runspace.DefaultRunspace,out record)?record:null;
  }
 }
 public void StartOwn() { GuardOwn(); if(!bootstrap||!GbBootstrapStartOwn(leaf)) {RevokeOwn();throw new InvalidOperationException("NativeStartUnconfirmed");} }
 public bool ReadyOwn() { try {GuardOwn();return bootstrap&&leaf!=IntPtr.Zero&&GbBootstrapReadyOwn(leaf);} catch {return false;} }
 public void BeginAccountOwn() {
  GuardOwn();
  if(!bootstrap||accountBeginning||!(bool)attempt["AccountSubmitted"]||attempt["Account"]!=null)
   throw new InvalidOperationException("NativeAccountPhaseInvalid");
  accountBeginning=true;
  if(!GbBootstrapBeginAccountOwn(leaf)){RevokeOwn();throw new InvalidOperationException("NativeAccountBeginUnconfirmed");}
 }
 public void AccountOwn() {
  GuardOwn();
  if(!bootstrap||!accountBeginning||originalAccount!=null||!(bool)attempt["AccountSubmitted"])
   throw new InvalidOperationException("NativeAccountPhaseInvalid");
  if(attempt["Account"]!=null) originalAccount=PSObject.AsPSObject(attempt["Account"]).BaseObject;
  if(originalAccount==null||originalAccount.GetType().FullName!="Microsoft.PowerShell.Commands.LocalUser")
   throw new InvalidOperationException("NativeOriginalAccountRequired");
  var account=PSObject.AsPSObject(originalAccount);
  var sid=account.Properties["SID"].Value as SecurityIdentifier;
  if((string)account.Properties["Name"].Value!=accountName||sid==null||
   (string)attempt["Owner"]!=Owner||(string)attempt["Name"]!=accountName||!GbBootstrapAccountOwn(leaf,sid.Value)) {
   RevokeOwn();throw new InvalidOperationException("NativeAccountUnconfirmed");
  }
 }
 public void BindOriginalOwn(uint pid,ulong made,ulong cookie) { GuardOwn(); if(!bootstrap||!GbBootstrapBindOwn(leaf,pid,made,cookie)) {RevokeOwn();throw new InvalidOperationException("NativeOriginalPeerUnconfirmed");} }
 public void BindOwn() { GuardOwn(); if(bootstrap||!GbControllerBindOwn(leaf)) {RevokeOwn();throw new InvalidOperationException("NativeBindUnconfirmed");} }
 public void SealOwn() { GuardOwn(); if(!bootstrap||!GbBootstrapSealOwn(leaf)) {RevokeOwn();throw new InvalidOperationException("NativeDeliveryUnconfirmed");} }
 public bool CurrentOwn() { try {GuardOwn();return leaf!=IntPtr.Zero&&GbNativeCurrentOwn(leaf);} catch {return false;} }
 public void RevokeOwn() {
  if(closed) return;
  revoked=true;try {stop.Set();} catch(ObjectDisposedException) {return;}
  if(leaf!=IntPtr.Zero) GbNativeRevokeOwn(leaf);
 }
 public bool CloseOwn() {
  if(closed) return true;
  RevokeOwn();
  if(submitted&&leaf!=IntPtr.Zero&&!GbNativeCloseOwn(leaf)) return false;
  leaf=IntPtr.Zero;closed=true;runspace.StateChanged-=StateChangedOwn;stop.Dispose();
  lock(Retained) Retained.Remove(runspace);
  return true;
 }
}
'@ -ErrorAction Stop
        }
        # Reserva visible antes del primer export. Las hojas fallidas quedan en el registro tipado.
        $global:GbGuestNativeCustody=$null
        $pins=New-Object byte[] 224
        for($i=0;$i -lt 7;$i++) {
            $stream=$record.Streams[$i]; $stream.Position=0
            $sha=[Security.Cryptography.SHA256]::Create()
            try { $hash=$sha.ComputeHash($stream) } finally {$sha.Dispose();$stream.Position=0}
            [Array]::Copy($hash,0,$pins,$i*32,32)
        }
        $stage=if($role -ceq 'Bootstrap'){$global:GbVmEnrollmentAttempt}else{$null}
        $global:GbGuestNativeCustody=[GbGuestNativeCustody]::ReserveOwn([IO.FileStream[]]$record.Streams.ToArray(),$pins,($role -ceq 'Bootstrap'),$record.Owner,$stage)
        if($role -ceq 'Bootstrap') { $global:GbGuestNativeCustody.StartOwn() }
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Reserved=$true;Pid=$global:GbGuestNativeCustody.Pid;
            Creation=$global:GbGuestNativeCustody.Creation;Correlation=$global:GbGuestNativeCustody.Correlation}
    } -ArgumentList $ownerId,$challenge,$role -ErrorAction Stop
}
$script:VmNativeCall={
    param($session,$ownerId,$challenge,$operation,$values)
    Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock {
        param($ownerId,$challenge,$operation,$values)
        if($ownerId -cnotmatch '^[0-9a-f]{32}$' -or $challenge -cnotmatch '^[0-9a-f]{64}$') {throw 'NativeRequestInvalid'}
        $type='GbGuestNativeCustody' -as [type]
        $record=if($type){[GbGuestNativeCustody]::OriginalOwn()}else{$null}
        if($operation -ceq 'Close' -and -not $record) {
            return [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Confirmed=$true}
        }
        if(-not $type -or $record -isnot $type -or $record.Owner -cne $ownerId) {
            throw 'NativeCustodyRequired'
        }
        switch -CaseSensitive ($operation) {
            'Original' {$record.BindOriginalOwn([uint32]$values[0],[uint64]$values[1],[uint64]$values[2])}
            'Bind' {$record.BindOwn()}
            'Seal' {$record.SealOwn()}
            'Current' {if(-not $record.CurrentOwn()){throw 'NativeCustodyRevoked'}}
            'Revoke' {$record.RevokeOwn()}
            'Close' {if(-not $record.CloseOwn()){throw 'NativeClosePending'}}
            default {throw 'NativeOperationInvalid'}
        }
        [pscustomobject]@{Owner=$ownerId;Challenge=$challenge;Confirmed=$true}
    } -ArgumentList $ownerId,$challenge,$operation,$values -ErrorAction Stop
}

function Revoke-VmGuestNativeOwn($owner) {
    $e=$owner.GuestEnrollment
    if (-not $e -or $e -isnot [Collections.IDictionary] -or
        -not $e.Contains('NativeBootstrapSubmitted') -or
        (-not $e.NativeBootstrapSubmitted -and -not $e.NativeControllerSubmitted)) { return $true }
    # Nueva admisión está vetada antes de tocar el canal; cleanup no necesita Current.
    $e.Revoked=$true; $e.Confirmed=$false
    if (-not $owner.Revoked -or -not [object]::ReferenceEquals((Get-VmOwnRecord $owner.Id),$owner) -or
        -not [object]::ReferenceEquals($e.Owner,$owner)) { $e.NativeRevokeUncertain=$true;return $false }
    if ($e.Contains('NativeRevokeSubmitted') -and $e.NativeRevokeSubmitted) {
        return (-not $e.NativeRevokeUncertain)
    }
    $e.NativeRevokeAttempts=[Collections.Generic.List[object]]::new()
    $e.NativeRevokeSubmitted=$true; $e.NativeRevokeUncertain=$false
    foreach ($role in @('Channel','Bootstrap')) {
        if (($role -ceq 'Channel' -and -not $e.NativeControllerSubmitted) -or
            ($role -ceq 'Bootstrap' -and -not $e.NativeBootstrapSubmitted)) { continue }
        $channel=$e[$role]; $session=if($channel){$channel.Session}else{$null}
        $attempt=@{Channel=$channel;Session=$session;Generation=$e.Generation;Submitted=$true;
            NativeSignalled=$false;RemoveSubmitted=$false;RemoveOutputs=[Collections.Generic.List[object]]::new();
            ConnectionClosed=$false;Cause=''}
        $e.NativeRevokeAttempts.Add($attempt)
        try {
            if (-not $channel -or -not [object]::ReferenceEquals($channel.Owner,$owner) -or
                $channel.Generation -ne $e.Generation -or
                $session -isnot [System.Management.Automation.Runspaces.PSSession] -or
                $session.InstanceId -ne $channel.Instance -or
                @($channel.Resources | Where-Object {[object]::ReferenceEquals($_,$session)}).Count -ne 1 -or
                $session.Runspace.ConnectionInfo -isnot [System.Management.Automation.Runspaces.VMConnectionInfo] -or
                $session.Runspace.ConnectionInfo.VMGuid -ne $owner.VmId) { throw 'NativeRevokeOriginalChannelUnknown' }
            if ([string]$session.Runspace.RunspaceStateInfo.State -ceq 'Opened' -and
                [string]$session.Availability -ceq 'Available') {
                try {
                    $challenge=New-VmEnrollmentChallengeOwn
                    $reply=@(& $script:VmNativeCall $session $owner.Id.ToString('N') $challenge 'Revoke' @())
                    if ($reply.Count -ne 1 -or $reply[0].Owner -cne $owner.Id.ToString('N') -or
                        $reply[0].Challenge -cne $challenge -or $reply[0].Confirmed -isnot [bool] -or
                        -not $reply[0].Confirmed) { throw 'NativeRevokeUnconfirmed' }
                    $attempt.NativeSignalled=$true
                } catch { $attempt.Cause='NativeRevokeSignalUncertain' }
            }
            if (-not $attempt.NativeSignalled) {
                $attempt.RemoveSubmitted=$true
                & $script:VmGuestRemove $session | ForEach-Object {$attempt.RemoveOutputs.Add($_)}
                # Estado de la referencia Runspace real, no Availability ni DTO remoto.
                $attempt.ConnectionClosed=([string]$session.Runspace.RunspaceStateInfo.State -ceq 'Closed')
                if (-not $attempt.ConnectionClosed) { throw 'NativeRevokeConnectionUncertain' }
            }
        } catch { $attempt.Cause=$_.Exception.Message;$e.NativeRevokeUncertain=$true }
        # Conserva session/Resources y hojas nativas; cerrar conexión no prueba exit.
    }
    return (-not $e.NativeRevokeUncertain)
}
