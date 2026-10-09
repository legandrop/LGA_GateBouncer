Set-StrictMode -Version Latest
# Aprovisionamiento local propio: importar no crea recursos ni habilita Start.
$script:VmOwners = @{}
$script:VmBoundary = @{ Busy=$false; Lease=$null; Switch=$null; SwitchId=[guid]::Empty;
    SwitchResources=[Collections.Generic.List[object]]::new();
    LeaseResources=[Collections.Generic.List[object]]::new();Version=[long]0;Frame=$null;LastTick=$null;ClockRevoked=$false;
    SwitchName=''; UnknownEffect=$false; Intents=0; Lost=$false }
$script:VmRoot = 'T:\LGA_GateBouncer_Lab'
$script:VmClock = { [long]([Diagnostics.Stopwatch]::GetTimestamp()*1000.0/[Diagnostics.Stopwatch]::Frequency) }
$script:VmPlatform = {
    if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { throw 'RebootPending' }
    if (-not (Get-Module -ListAvailable Hyper-V)) { throw 'HyperVModuleMissing' }
    $service=Get-Service vmms -ErrorAction Stop
    if ([string]$service.Status -cne 'Running') { throw 'VmmsNotRunning' }
    if ([IO.DriveInfo]::new('T:\').DriveType -ne [IO.DriveType]::Fixed) { throw 'RootNotLocal' }
    $path=$script:VmRoot
    while ($path) {
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'RootCustodyUnconfirmed' }
        $path=[IO.Path]::GetDirectoryName($entry.FullName.TrimEnd('\'))
    }
}
$script:VmLeaseCreate = {
    [IO.FileStream]::new((Join-Path $script:VmRoot 'provisioning-lease.json'),
        [IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
}
$script:VmLeaseWrite = {
    param($lease,[string]$line)
    $bytes=[Text.Encoding]::UTF8.GetBytes($line+"`n")
    $lease.Write($bytes,0,$bytes.Length); $lease.Flush($true)
}
$script:VmLeaseCheck = { param($lease) if (-not $lease.CanWrite -or -not $lease.CanRead) { throw 'LeaseLost' } }
$script:VmPathCheck = {
    param([string]$target,[bool]$mustExist)
    $path=[IO.Path]::GetFullPath($target)
    if (-not $path.StartsWith($script:VmRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'PathOutsideBoundary' }
    if ((Test-Path -LiteralPath $path -ErrorAction Stop) -ne $mustExist) { throw 'PathExistenceChanged' }
    while ($path) {
        if (Test-Path -LiteralPath $path -ErrorAction Stop) {
            $entry=Get-Item -LiteralPath $path -ErrorAction Stop
            if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'PathCustodyUnconfirmed' }
        }
        $path=[IO.Path]::GetDirectoryName($path.TrimEnd('\'))
    }
}
$script:VmType = { param($value,[string]$name) $null -ne $value -and $value.GetType().FullName -ceq ('Microsoft.HyperV.PowerShell.'+$name) }
$script:VmNewSwitch = { param($name) Hyper-V\New-VMSwitch -Name $name -SwitchType Private -ErrorAction Stop }
$script:VmNew = {
    param($name,$path,$switch)
    Hyper-V\New-VM -Name $name -Generation 2 -MemoryStartupBytes 8589934592 -NoVHD -SwitchName $switch -Path $path -ErrorAction Stop
}
$script:VmSetCpu = { param($vm) Hyper-V\Set-VMProcessor -VM $vm -Count 4 -ErrorAction Stop }
$script:VmAll = { @(Hyper-V\Get-VM -ErrorAction Stop) }
$script:VmAllSwitch = { @(Hyper-V\Get-VMSwitch -ErrorAction Stop) }
$script:VmAllAdapters = { @(Hyper-V\Get-VMNetworkAdapter -All -ErrorAction Stop) }
$script:VmAdapters = { param($vm) @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop) }
$script:VmDisks = { param($vm) @(Hyper-V\Get-VMHardDiskDrive -VM $vm -ErrorAction Stop) }
$script:VmSnapshots = { param($vm) @(Hyper-V\Get-VMSnapshot -VM $vm -ErrorAction Stop) }
$script:VmRemove = { param($vm) Hyper-V\Remove-VM -VM $vm -Confirm:$false -ErrorAction Stop }

function Get-VmOwnRecord([guid]$OwnerId) {
    if (-not $script:VmOwners.ContainsKey($OwnerId)) { throw 'OwnerUnknown' }
    $script:VmOwners[$OwnerId]
}
function Get-VmOwnView($owner) {
    # IDs son datos diagnósticos: ninguna referencia VM, issuer ni permiso guest.
    $state=if ($script:VmBoundary.Busy -and -not $owner.Revoked) {'Observing'} else {$owner.State}
    [pscustomobject]@{OwnerId=$owner.Id;GuestKind=$owner.Kind;VmId=$owner.VmId;
        SwitchId=$script:VmBoundary.SwitchId;State=$state;Cause=$owner.Cause;
        Generation=$owner.Generation;Revoked=$owner.Revoked;CleanupPending=$owner.Pending;
        VmRemovalObserved=$owner.Removed;SwitchRemovalObserved=$false;
        BootObserved=[bool](-not $script:VmBoundary.Busy -and -not $owner.Revoked -and $owner.GuestObservation -and
            $owner.GuestObservation.Confirmed -and $owner.GuestObservation.Observed -le $owner.Observed -and
            $owner.Observed-$owner.GuestObservation.Observed -lt 5000);EnrollmentObserved=$false;
        StartSubmitted=[bool]($owner.Storage -and $owner.Storage.StartSubmitted)}
}
function Set-VmOwnRevoked($owner,[string]$cause) {
    if ($cause -in @('LeaseLost','LeaseMissing','RootCustodyUnconfirmed')) { $script:VmBoundary.Lost=$true }
    if (-not $owner.Revoked) {
        $owner.Revoked=$true
        if ($script:VmBoundary.Version -lt [long]::MaxValue) { $script:VmBoundary.Version++ } else { $script:VmBoundary.Lost=$true }
        if ($owner.Generation -lt [long]::MaxValue) { $owner.Generation++ }
    }
    $owner.State='CleanupPending'; $owner.Cause=$cause
    $owner.Pending=[bool]($owner.Resources.Count -or $script:VmBoundary.Lease -or $script:VmBoundary.UnknownEffect)
}
function Read-VmOwnClock([bool]$cleanup=$false) {
    $now=[long](& $script:VmClock)
    if ($null -ne $script:VmBoundary.LastTick -and $now -lt $script:VmBoundary.LastTick) {
        $script:VmBoundary.ClockRevoked=$true
        if (-not $cleanup) { throw 'ClockReversed' }
    } else { $script:VmBoundary.LastTick=$now }
    if ($script:VmBoundary.ClockRevoked -and -not $cleanup) { throw 'ClockReversed' }
    $now
}
function Test-VmOwnCurrent($owner,[long]$generation) {
    if ($owner.Revoked -or $owner.Generation -ne $generation -or $script:VmBoundary.Lost) { throw 'OwnerRevoked' }
    $now=Read-VmOwnClock
    if ($now -lt $owner.Created -or $now -lt $owner.Observed -or $now -ge $owner.Deadline -or $now-$owner.Observed -gt 5000) { throw 'LeaseExpired' }
    if (-not $script:VmBoundary.Lease) { throw 'LeaseMissing' }
    & $script:VmLeaseCheck $script:VmBoundary.Lease
}
function Enter-VmOwnFrame($owner,[bool]$cleanup) {
    $peers=@($script:VmOwners.Values | Where-Object { $_.Id -ne $owner.Id -and $_.VmId -ne [guid]::Empty -and -not $_.Removed } |
        ForEach-Object { @{Ref=$_;Generation=$_.Generation} })
    $script:VmBoundary.Frame=@{Owner=$owner;Generation=$owner.Generation;Version=$script:VmBoundary.Version;Cleanup=$cleanup;Peers=$peers;Attempt=$null;PreparingStorage=$null}
}
function Test-VmOwnFrame {
    $frame=$script:VmBoundary.Frame
    if (-not $frame -or $script:VmBoundary.Version -ne $frame.Version -or $script:VmBoundary.Lost) { throw 'FrameRevoked' }
    $null=Read-VmOwnClock $frame.Cleanup
    if (-not $frame.Cleanup -and $frame.Owner.State -cne 'Reserving' -and $script:VmBoundary.UnknownEffect -and
        -not (Test-VmStorageAttemptFrame $frame)) { throw 'EffectUnobserved' }
    & $script:VmPlatform
    if ($frame.Cleanup) {
        if (-not $script:VmBoundary.Lease) { throw 'LeaseMissing' }
        & $script:VmLeaseCheck $script:VmBoundary.Lease
    } else {
        Test-VmOwnCurrent $frame.Owner $frame.Generation
        foreach ($peer in $frame.Peers) {
            try { Test-VmOwnCurrent $peer.Ref $peer.Generation }
            catch { Set-VmOwnRevoked $peer.Ref $_.Exception.Message; throw }
        }
    }
    if ($script:VmBoundary.SwitchId -ne [guid]::Empty -and [guid]$script:VmBoundary.Switch.Id -ne $script:VmBoundary.SwitchId) { throw 'SwitchIdentityChanged' }
    foreach ($member in @($script:VmOwners.Values | Where-Object { $_.VmId -ne [guid]::Empty -and -not $_.Removed })) {
        if ($member.Resources.Count -ne 1 -or [guid]$member.Resources[0].Ref.Id -ne $member.VmId -or
            -not ([string]$member.Resources[0].Ref.ComputerName).Equals([Environment]::MachineName,[StringComparison]::OrdinalIgnoreCase)) { throw 'VmIdentityChanged' }
    }
    if ($script:VmBoundary.Version -ne $frame.Version) { throw 'FrameRevoked' }
    $null=Read-VmOwnClock $frame.Cleanup
}
function Read-VmOwnPort([scriptblock]$port,[object[]]$arguments=@()) {
    Test-VmOwnFrame
    $values=@(& $port @arguments)
    Test-VmOwnFrame
    $values
}
function Confirm-VmOwnSwitch {
    if (-not $script:VmBoundary.Switch -or -not (& $script:VmType $script:VmBoundary.Switch 'VMSwitch')) { throw 'SwitchMissing' }
    if ([guid]$script:VmBoundary.Switch.Id -ne $script:VmBoundary.SwitchId) { throw 'SwitchIdentityChanged' }
    $matches=@(Read-VmOwnPort $script:VmAllSwitch | Where-Object { [guid]$_.Id -eq $script:VmBoundary.SwitchId })
    if ($matches.Count -ne 1 -or -not (& $script:VmType $matches[0] 'VMSwitch') -or
        [string]$matches[0].SwitchType -cne 'Private' -or [string]$matches[0].Name -cne $script:VmBoundary.SwitchName) { throw 'SwitchChanged' }
    $adapters=@(Read-VmOwnPort $script:VmAllAdapters | Where-Object { [guid]$_.SwitchId -eq $script:VmBoundary.SwitchId })
    $expected=@($script:VmOwners.Values | Where-Object { $_.VmId -ne [guid]::Empty -and -not $_.Removed })
    if ($adapters.Count -ne $expected.Count) { throw 'TopologyCardinalityChanged' }
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($adapter in $adapters) {
        if (-not (& $script:VmType $adapter 'VMNetworkAdapter')) { throw 'ForeignAdapter' }
        $own=@($expected | Where-Object { $_.VmId -eq [guid]$adapter.VMId -and $_.AdapterId -ceq [string]$adapter.Id })
        if ($own.Count -ne 1 -or -not $seen.Add(([guid]$adapter.VMId).ToString('D')+'|'+[string]$adapter.Id)) { throw 'ForeignAdapter' }
    }
}
function Capture-VmOwnAdapter($owner) {
    $adapters=@(Read-VmOwnPort $script:VmAdapters @($owner.Resources[0].Ref))
    if ($adapters.Count -ne 1 -or -not (& $script:VmType $adapters[0] 'VMNetworkAdapter') -or
        [guid]$adapters[0].VMId -ne $owner.VmId -or [guid]$adapters[0].SwitchId -ne $script:VmBoundary.SwitchId -or
        ([string]$adapters[0].Id).Length -lt 1 -or ([string]$adapters[0].Id).Length -gt 256) { throw 'VmTopologyChanged' }
    $owner.AdapterId=[string]$adapters[0].Id
}
function Confirm-VmOwnMachine($owner,[long]$expectedCpu=4) {
    if ($owner.Resources.Count -ne 1) { throw 'VmCardinality' }
    $resource=$owner.Resources[0]
    if (-not (& $script:VmType $resource.Ref 'VirtualMachine') -or [guid]$resource.Ref.Id -ne $owner.VmId -or $owner.VmId -eq [guid]::Empty) { throw 'VmIdentityChanged' }
    $matches=@(Read-VmOwnPort $script:VmAll | Where-Object { [guid]$_.Id -eq $owner.VmId })
    if ($matches.Count -ne 1 -or -not (& $script:VmType $matches[0] 'VirtualMachine')) { throw 'VmObservationUnconfirmed' }
    $vm=$matches[0]
    $prefix=[IO.Path]::GetFullPath($owner.Path).TrimEnd('\')+'\'
    $actual=[IO.Path]::GetFullPath([string]$vm.Path).TrimEnd('\')+'\'
    if (-not $actual.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase) -or
        [string]$vm.Name -cne $owner.Name -or -not ([string]$vm.ComputerName).Equals([Environment]::MachineName,[StringComparison]::OrdinalIgnoreCase) -or
        [int]$vm.Generation -ne 2 -or [long]$vm.MemoryStartup -ne 8589934592 -or
        [bool]$vm.DynamicMemoryEnabled -or [long]$vm.ProcessorCount -ne $expectedCpu) { throw 'VmConfigurationChanged' }
    Read-VmOwnPort $script:VmPathCheck @($owner.Path,$true) | Out-Null
    Read-VmOwnPort $script:VmPathCheck @([string]$vm.Path,$true) | Out-Null
    if (@(Read-VmOwnPort $script:VmSnapshots @($resource.Ref)).Count -ne 0) { throw 'VmStorageChanged' }
    if ($owner.Storage) { Confirm-VmStorageOwn $owner $vm }
    elseif ([string]$vm.State -cne 'Off' -or @(Read-VmOwnPort $script:VmDisks @($resource.Ref)).Count -ne 0) { throw 'VmStorageChanged' }
    $adapters=@(Read-VmOwnPort $script:VmAdapters @($resource.Ref))
    if ($adapters.Count -ne 1 -or -not (& $script:VmType $adapters[0] 'VMNetworkAdapter') -or
        [guid]$adapters[0].VMId -ne $owner.VmId -or [guid]$adapters[0].SwitchId -ne $script:VmBoundary.SwitchId -or [string]$adapters[0].Id -cne $owner.AdapterId) { throw 'VmTopologyChanged' }
    Confirm-VmOwnSwitch
}
function Write-VmOwnIntent($owner,[string]$operation) {
    Test-VmOwnFrame
    $line=@{Owner=$owner.Id.ToString('D');Operation=$operation;Kind=$owner.Kind;Name=$owner.Name;Path=$owner.Path}|ConvertTo-Json -Compress
    try { & $script:VmLeaseWrite $script:VmBoundary.Lease $line }
    catch { $script:VmBoundary.Lost=$true; throw 'IntentFlushUnconfirmed' }
    Test-VmOwnFrame
}
function Open-GbOwnVmProvisioning {
    [CmdletBinding()] param([Parameter(Mandatory)][ValidateSet('Windows','Linux')][string]$GuestKind)
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    if ($script:VmBoundary.UnknownEffect -or $script:VmBoundary.Lost -or $script:VmBoundary.ClockRevoked) { throw 'BoundaryQuarantined' }
    if (@($script:VmOwners.Values | Where-Object { $_.Revoked -and $_.Pending }).Count) { throw 'BoundaryQuarantined' }
    if ($script:VmBoundary.Intents -ge 2 -or @($script:VmOwners.Values | Where-Object { $_.Kind -ceq $GuestKind }).Count) { throw 'ProvisioningBudget' }
    $script:VmBoundary.Busy=$true
    try { $now=Read-VmOwnClock } catch { $script:VmBoundary.Busy=$false; throw }
    $id=[guid]::NewGuid(); $suffix=$id.ToString('N')
    $owner=@{Id=$id;Kind=$GuestKind;VmId=[guid]::Empty;Name=('GateBouncer-'+$GuestKind+'-'+$suffix);
        Path=(Join-Path $script:VmRoot $suffix);Created=$now;Observed=$now;Deadline=$now+10000;
        Generation=[long]0;Revoked=$false;State='Reserving';Cause='';Pending=$false;
        Resources=[Collections.Generic.List[object]]::new();Removed=$false;RemoveSubmitted=$false;AdapterId='';Storage=$null;
        GuestPackage=$null;GuestCredential=$null;GuestObservation=$null}
    $script:VmOwners[$id]=$owner
    try {
        & $script:VmPlatform
        if ($owner.Revoked) { throw 'OwnerRevoked' }
        if (-not $script:VmBoundary.Lease) {
            # CreateNew nunca abre/adopta un sentinel previo; el archivo persiste tras crash.
            $script:VmBoundary.UnknownEffect=$true
            & $script:VmLeaseCreate | ForEach-Object {
                $script:VmBoundary.LeaseResources.Add($_)
            }
            if ($script:VmBoundary.LeaseResources.Count -ne 1) { throw 'LeaseCardinality' }
            $script:VmBoundary.Lease=$script:VmBoundary.LeaseResources[0]
            & $script:VmLeaseCheck $script:VmBoundary.Lease
            $script:VmBoundary.UnknownEffect=$false
        }
        Enter-VmOwnFrame $owner $false
        Test-VmOwnFrame
        $script:VmBoundary.Intents++
        if (-not $script:VmBoundary.Switch) {
            $script:VmBoundary.SwitchName='GateBouncer-Private-'+$suffix
            Write-VmOwnIntent $owner 'CreateSwitch'
            $script:VmBoundary.UnknownEffect=$true
            & $script:VmNewSwitch $script:VmBoundary.SwitchName | ForEach-Object {
                $script:VmBoundary.SwitchResources.Add($_)
            }
            if ($script:VmBoundary.SwitchResources.Count -ne 1) { throw 'SwitchCardinality' }
            $script:VmBoundary.Switch=$script:VmBoundary.SwitchResources[0]
            if (-not (& $script:VmType $script:VmBoundary.Switch 'VMSwitch') -or [guid]$script:VmBoundary.Switch.Id -eq [guid]::Empty) { throw 'SwitchCreationUnconfirmed' }
            $script:VmBoundary.SwitchId=[guid]$script:VmBoundary.Switch.Id
            Test-VmOwnFrame
            Confirm-VmOwnSwitch
            $script:VmBoundary.UnknownEffect=$false
        } else {
            Confirm-VmOwnSwitch
            foreach ($peer in $script:VmBoundary.Frame.Peers) { Confirm-VmOwnMachine $peer.Ref }
            Test-VmOwnFrame
        }
        Read-VmOwnPort $script:VmPathCheck @($owner.Path,$false) | Out-Null
        Write-VmOwnIntent $owner 'CreateVm'
        $script:VmBoundary.UnknownEffect=$true
        & $script:VmNew $owner.Name $owner.Path $script:VmBoundary.SwitchName | ForEach-Object {
            # Capturar primero, incluso retorno tardío o cardinalidad inválida.
            $owner.Resources.Add(@{Ref=$_})
        }
        if ($owner.Resources.Count -ne 1 -or -not (& $script:VmType $owner.Resources[0].Ref 'VirtualMachine')) { throw 'VmCreationUnconfirmed' }
        $owner.VmId=[guid]$owner.Resources[0].Ref.Id
        if ($owner.VmId -eq [guid]::Empty) { throw 'VmCreationUnconfirmed' }
        Test-VmOwnFrame
        Capture-VmOwnAdapter $owner
        Confirm-VmOwnSwitch
        Read-VmOwnPort $script:VmPathCheck @($owner.Path,$true) | Out-Null
        foreach ($peer in $script:VmBoundary.Frame.Peers) { Confirm-VmOwnMachine $peer.Ref }
        # New-VM parte de un procesador; comprobar frontera completa antes de mutarlo.
        Confirm-VmOwnMachine $owner 1
        Test-VmOwnFrame
        & $script:VmSetCpu $owner.Resources[0].Ref | Out-Null
        Test-VmOwnFrame
        foreach ($peer in $script:VmBoundary.Frame.Peers) { Confirm-VmOwnMachine $peer.Ref }
        Confirm-VmOwnMachine $owner
        Test-VmOwnFrame
        $script:VmBoundary.UnknownEffect=$false
        $owner.Observed=Read-VmOwnClock
        Test-VmOwnFrame
        $owner.Deadline=$owner.Created+60000
        $owner.State='ProvisionedOff'; $owner.Cause='GuestBootEnrollmentMissing'; $owner.Pending=$true
    } catch {
        Set-VmOwnRevoked $owner $_.Exception.Message
        if ($_.Exception.Message -in @('LeaseLost','LeaseMissing','RootCustodyUnconfirmed')) { $script:VmBoundary.Lost=$true }
    } finally { $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false }
    Get-VmOwnView $owner
}
function Get-GbOwnVmProvisioningState {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    $owner=Get-VmOwnRecord $OwnerId
    if ($script:VmBoundary.Busy) { return Get-VmOwnView $owner }
    if (-not $owner.Revoked) {
        $script:VmBoundary.Busy=$true
        try {
            Enter-VmOwnFrame $owner $false
            Test-VmOwnFrame
            Confirm-VmOwnMachine $owner
            foreach ($peer in $script:VmBoundary.Frame.Peers) { Confirm-VmOwnMachine $peer.Ref }
            Test-VmOwnFrame
            $owner.Observed=Read-VmOwnClock
        } catch { Set-VmOwnRevoked $owner $_.Exception.Message }
        finally { $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false }
    }
    Get-VmOwnView $owner
}
function Revoke-GbOwnVmProvisioning {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    $owner=Get-VmOwnRecord $OwnerId
    Set-VmOwnRevoked $owner 'Cancelled'
    Get-VmOwnView $owner
}
function Close-GbOwnVmProvisioning {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    $owner=Get-VmOwnRecord $OwnerId
    Set-VmOwnRevoked $owner 'Cancelled'
    if ($script:VmBoundary.Busy) { return Get-VmOwnView $owner }
    if ($owner.GuestObservation) {
        try { Close-VmGuestObservationOwn $owner }
        catch { $owner.Cause=$_.Exception.Message; $owner.Pending=$true; return Get-VmOwnView $owner }
    }
    # Un intento de almacenamiento conserva toda custodia; nunca usa el retiro noVHD.
    if ($owner.Storage) {
        $owner.State='CleanupPending'; $owner.Cause='StorageCustodyRetained'; $owner.Pending=$true
        return Get-VmOwnView $owner
    }
    $script:VmBoundary.Busy=$true
    try {
        Enter-VmOwnFrame $owner $true
        Test-VmOwnFrame
        if ($owner.Resources.Count -ne 1 -or $owner.VmId -eq [guid]::Empty) { throw 'VmCleanupUnconfirmed' }
        if (-not $owner.Removed) {
            if (-not $owner.RemoveSubmitted) {
                Confirm-VmOwnMachine $owner
                # Recheck completo antes de Remove: sin discos ni checkpoints que fusionar.
                Confirm-VmOwnMachine $owner
                $owner.RemoveSubmitted=$true
                & $script:VmRemove $owner.Resources[0].Ref | Out-Null
                Test-VmOwnFrame
            }
            $present=@(Read-VmOwnPort $script:VmAll | Where-Object { [guid]$_.Id -eq $owner.VmId })
            if ($present.Count -ne 0) { throw 'VmRemovalUnconfirmed' }
            $owner.Removed=$true
        }
        # No hay exclusión administrativa atómica sobre adapters: nunca RemoveSwitch.
        $owner.Cause=if ($script:VmBoundary.UnknownEffect) {'EffectUnobserved'} else {'SwitchCustodyRetained'}
        $owner.Pending=$true; $owner.State='CleanupPending'
    } catch { $owner.Cause=$_.Exception.Message; $owner.Pending=$true }
    finally { $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false }
    Get-VmOwnView $owner
}
. (Join-Path $PSScriptRoot 'OwnVmBootAdapters.ps1')
. (Join-Path $PSScriptRoot 'OwnVmGuestObservation.ps1')
Export-ModuleMember -Function Open-GbOwnVmProvisioning,Get-GbOwnVmProvisioningState,Revoke-GbOwnVmProvisioning,Close-GbOwnVmProvisioning,Prepare-GbOwnVmBoot,Start-GbOwnVmBoot
