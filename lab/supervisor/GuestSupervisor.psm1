Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'GuestCommands.ps1')
$script:GbOwners = @{}
# Puertos privados con implementacion real; no se exporta un setter para reemplazarlos.
$script:GbClock = { [long]([Diagnostics.Stopwatch]::GetTimestamp() * 1000.0 / [Diagnostics.Stopwatch]::Frequency) }
$script:GbCreate = { param($vm,$credential) Microsoft.PowerShell.Core\New-PSSession -VMId $vm -Credential $credential -ErrorAction Stop }
$script:GbRemove = { param($session) Microsoft.PowerShell.Core\Remove-PSSession -Session $session -ErrorAction Stop }
$script:GbRemote = { param($session,$challenge) Microsoft.PowerShell.Core\Invoke-Command -Session $session -ScriptBlock $script:GbBootstrapCommand -ArgumentList $challenge -ErrorAction Stop }
$script:GbInventory = {
    param($vmId)
    $vm = Hyper-V\Get-VM -Id $vmId -ErrorAction Stop
    if ($vm.Id -ne $vmId -or [string]$vm.State -ne 'Running') { throw 'VmNotRunning' }
    $adapters = @(Hyper-V\Get-VMNetworkAdapter -VM $vm -ErrorAction Stop)
    if ($adapters.Count -ne 1) { throw 'TopologyUnsupported' }
    $switch = Hyper-V\Get-VMSwitch -Id $adapters[0].SwitchId -ErrorAction Stop
    if ([string]$switch.SwitchType -ne 'Private') { throw 'TopologyNotPrivate' }
    [pscustomobject]@{ VmId = [guid]$vm.Id; Uptime = [long]$vm.Uptime.Ticks;
        Switch = [guid]$switch.Id; Mac = ([string]$adapters[0].MacAddress -replace '[-:]','').ToUpperInvariant() }
}
$script:GbInspect = {
    param($session,$vmId)
    if ($session -isnot [System.Management.Automation.Runspaces.PSSession]) { throw 'SessionTypeInvalid' }
    $connection = $session.Runspace.ConnectionInfo
    if ($connection -isnot [System.Management.Automation.Runspaces.VMConnectionInfo] -or $connection.VMGuid -ne $vmId) { throw 'SessionVmMismatch' }
    if ([string]$session.Runspace.RunspaceStateInfo.State -ne 'Opened') { throw 'SessionNotOpened' }
    if ([string]$session.Availability -ne 'Available') { throw 'SessionBusy' }
    [guid]$session.InstanceId
}
. (Join-Path $PSScriptRoot 'OwnCaptureComposition.ps1')

function Get-GbOwner([guid]$OwnerId) {
    if (-not $script:GbOwners.ContainsKey($OwnerId)) { throw 'OwnerUnknown' }
    $script:GbOwners[$OwnerId]
}
function Get-GbView($owner) {
    [pscustomobject]@{ OwnerId = $owner.Id; VmId = $owner.VmId; InstanceId = $owner.Instance;
        State = $owner.State; Cause = $owner.Cause; CleanupPending = $owner.CleanupPending;
        Generation = $owner.Generation; StartSubmitted = $owner.StartSubmitted;
        StopObserved = $owner.StopObserved; FileFinal = $owner.FileFinal;
        MissingComponents = @($script:GbRequiredComponents) }
}
function Set-GbInvalid($owner,[string]$cause) {
    $owner.Revoked = $true
    $owner.State = 'Revoked'
    $owner.Cause = $cause
    if ($owner.Session -or $owner.Gate) { $owner.CleanupPending = $true }
}
function Test-GbCurrent($owner,[long]$generation,[bool]$cleanup = $false) {
    if ((-not $cleanup -and $owner.Revoked) -or $owner.Generation -ne $generation) { throw 'OwnerRevoked' }
    $now = & $script:GbClock
    if (-not $cleanup -and ($now -lt $owner.Created -or $now -ge $owner.Deadline -or $now - $owner.Observed -gt 5000)) {
        Set-GbInvalid $owner 'LeaseExpired'; throw 'LeaseExpired'
    }
    if (-not $owner.Session) { throw 'SessionMissing' }
    $instance = & $script:GbInspect $owner.Session $owner.VmId
    if ($instance -ne $owner.Instance) { Set-GbInvalid $owner 'InstanceChanged'; throw 'InstanceChanged' }
    if ($owner.Enrollment) { Confirm-GbEnrollmentOwn $owner $cleanup }
}
function Confirm-GbEnrollmentOwn($owner,[bool]$cleanup=$false) {
    $e=$owner.Enrollment
    if (-not $e -or -not $e.Issuer -or -not [object]::ReferenceEquals($e.Supervisor,$owner) -or
        -not [object]::ReferenceEquals($e.Channel.Session,$owner.Session) -or $e.Owner.VmId -ne $owner.VmId -or
        $e.Channel.Instance -ne $owner.Instance) { throw 'EnrollmentRequired' }
    & $e.Issuer { param($bound,$closing) Confirm-VmGuestEnrollmentOwn $bound $closing } $e $cleanup
}
function Confirm-GbBootstrap($owner,[long]$generation) {
    $inventory = & $script:GbInventory $owner.VmId
    Test-GbCurrent $owner $generation
    if ($inventory.Mac -ne $owner.Plan.Mac -or $inventory.VmId -ne $owner.VmId) { throw 'TopologyChanged' }
    if ($owner.Inventory -and ($inventory.Switch -ne $owner.Inventory.Switch -or $inventory.Uptime -lt $owner.Inventory.Uptime)) { throw 'VmCycleChanged' }
    $random = New-Object byte[] 32
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($random) } finally { $rng.Dispose() }
    $challenge = ([BitConverter]::ToString($random) -replace '-','').ToLowerInvariant()
    $reply = @(& $script:GbRemote $owner.Session $challenge)
    Test-GbCurrent $owner $generation
    if ($reply.Count -ne 1) { throw 'BootstrapCardinality' }
    $reply = $reply[0]
    if ($reply.Challenge -cne $challenge -or $reply.GuestNonce -cnotmatch '^[0-9a-f]{64}$' -or $reply.GuestNonce -eq $owner.Nonce) { throw 'ChallengeMismatch' }
    if ($reply.Hash -cne $owner.Plan.Hash -or $reply.UserSid -cne $owner.Plan.Sid -or [long]$reply.Boot -le 0) { throw 'GuestBundleMismatch' }
    if ($owner.Boot -and $owner.Boot -ne [long]$reply.Boot) { throw 'GuestBootChanged' }
    $nics = @($reply.Nics)
    if ($nics.Count -gt 16 -or @($nics | Where-Object { $_.Mac -eq $inventory.Mac }).Count -ne 1) { throw 'GuestInterfaceMismatch' }
    $nic = @($nics | Where-Object { $_.Mac -eq $inventory.Mac })[0]
    if ([guid]$nic.Guid -eq [guid]::Empty -or [int]$nic.Index -le 0 -or ([string]$nic.Name).Length -gt 256) { throw 'GuestInterfaceInvalid' }
    if ($owner.Nic -and ($nic.Guid -ne $owner.Nic.Guid -or $nic.Index -ne $owner.Nic.Index -or $nic.Name -cne $owner.Nic.Name)) { throw 'GuestInterfaceChanged' }
    $after = & $script:GbInventory $owner.VmId
    Test-GbCurrent $owner $generation
    if ($after.VmId -ne $inventory.VmId -or $after.Switch -ne $inventory.Switch -or $after.Mac -ne $inventory.Mac -or $after.Uptime -lt $inventory.Uptime) { throw 'TopologyChanged' }
    $owner.Inventory = $after; $owner.Nic = @{Guid=[guid]$nic.Guid;Index=[int]$nic.Index;Name=[string]$nic.Name}; $owner.Boot = [long]$reply.Boot; $owner.Nonce = $reply.GuestNonce
    $owner.Observed = & $script:GbClock
}
function Close-GbOwnResource($owner) {
    if ($owner.Busy) { $owner.CleanupPending = [bool]$owner.Session; return }
    if ($owner.Gate) { $owner.CleanupPending = $true; return }
    foreach ($entry in $owner.Resources) {
        if (-not $entry.Pending) { continue }
        if ($owner.Enrollment) { $entry.Pending=$false; $entry.Session=$null; continue }
        $owner.Busy = $true
        try {
            & $script:GbRemove $entry.Session
            $entry.Pending = $false; $entry.Session = $null
        } catch { $owner.CleanupPending = $true; $owner.Cause = 'SessionCloseUnconfirmed' }
        finally { $owner.Busy = $false }
    }
    $owner.CleanupPending = @($owner.Resources | Where-Object { $_.Pending }).Count -gt 0
    if (-not $owner.CleanupPending) { $owner.Session = $null }
    if (-not $owner.CleanupPending) {
        try {
            if ($owner.CapturePackage) {
                if (-not $owner.Enrollment) {
                    foreach ($stream in $owner.CapturePackage.Streams) { $stream.Dispose() }
                    foreach ($parent in $owner.CapturePackage.Parents) { $parent.Dispose() }
                }
                $owner.CapturePackage.Streams.Clear(); $owner.CapturePackage=$null
            }
            $owner.CaptureCancel.Dispose()
            $owner.State = 'Closed'
        } catch { $owner.CleanupPending=$true; $owner.Cause='PackageCloseUnconfirmed' }
    }
}

function Open-GbWindowsSupervisor {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$VmId, [Parameter(Mandatory)][pscredential]$Credential,
        [Parameter(Mandatory)][guid]$LabId, [Parameter(Mandatory)][string]$BootstrapHash,
        [Parameter(Mandatory)][string]$TestMac, [Parameter(Mandatory)][string]$GuestUserSid,
        [string]$CaptureLocal='', [string]$CapturePeer='')
    if ($VmId -eq [guid]::Empty -or $LabId -eq [guid]::Empty -or $BootstrapHash -cnotmatch '^[0-9A-F]{64}$' -or $TestMac -cnotmatch '^[0-9A-F]{12}$' -or $GuestUserSid -cnotmatch '^S-1-5-[0-9-]{1,160}$') { throw 'PlanInvalid' }
    if (@($script:GbOwners.Values | Where-Object { $_.VmId -eq $VmId -and $_.State -ne 'Closed' }).Count) { throw 'VmOwnershipPending' }
    $now = & $script:GbClock
    $owner = @{ Id = [guid]::NewGuid(); VmId = $VmId; LabId = $LabId; Instance = [guid]::Empty;
        Session = $null; Resources = [Collections.Generic.List[object]]::new(); Inventory = $null; Nic = $null; Gate = $null; Run = [guid]::Empty; Boot = [long]0; Nonce = '';
        Plan = @{ Hash = $BootstrapHash; Mac = $TestMac; Sid = $GuestUserSid }; State = 'CreatingWindows'; Cause = '';
        Created = $now; Observed = $now; Deadline = $now + 10000; Generation = [long]0;
        Revoked = $false; Busy = $true; CleanupPending = $false; StartSubmitted = $false;
        StopObserved = $false; FileFinal = $false; CapturePackage=$null;
        CaptureLocal=$CaptureLocal;CapturePeer=$CapturePeer;CaptureCancel=[Threading.CancellationTokenSource]::new();Conversion=$null;Enrollment=$null }
    $script:GbOwners[$owner.Id] = $owner
    try {
        $owner.Inventory = & $script:GbInventory $VmId
        if ($owner.Revoked) { throw 'OwnerRevoked' }
        & $script:GbCreate $VmId $Credential | ForEach-Object {
            $owner.Resources.Add(@{ Session = $_; Pending = $true })
            $owner.Session = $_
        }
        if ($owner.Resources.Count -ne 1) { throw 'SessionCardinality' }
        if ($owner.Revoked) { throw 'OwnerRevoked' }
        $owner.Instance = & $script:GbInspect $owner.Session $VmId
        Confirm-GbBootstrap $owner 0
        $owner.Deadline = $owner.Created + 60000
        $owner.State = 'WindowsOwned'; $owner.Cause = 'DualAdmissionNotComplete'
    } catch {
        Set-GbInvalid $owner 'WindowsCreationFailed'
    } finally {
        $Credential = $null
        $owner.Busy = $false
        if ($owner.Revoked) { Close-GbOwnResource $owner }
    }
    # OwnerId identifica el recurso provisional Windows; nunca una admision dual.
    Get-GbView $owner
}
function Get-GbLabSupervisorState {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    Get-GbView (Get-GbOwner $OwnerId)
}
function Invoke-GbLabCommand {
    [CmdletBinding()]
    param([Parameter(Mandatory)][guid]$OwnerId, [Parameter(Mandatory)][long]$Generation,
        [Parameter(Mandatory)][guid]$AcquisitionRunId,
        [Parameter(Mandatory)][ValidateSet('WindowsStatus','PrepareCapture','StartCapture','CaptureStatus','StopCapture','ConvertCapture','CleanupCapture')][string]$Operation)
    $owner = Get-GbOwner $OwnerId
    if ($owner.Busy) { throw 'PipelineBusy' }
    $owner.Busy = $true
    try {
        $cleanup = $Operation -in @('StopCapture','CleanupCapture')
        Test-GbCurrent $owner $Generation $cleanup
        if ($Operation -ne 'WindowsStatus') { Confirm-GbEnrollmentOwn $owner $cleanup }
        if (-not $cleanup) { Confirm-GbBootstrap $owner $Generation }
        if ($Operation -eq 'WindowsStatus') { return Get-GbView $owner }
        # La entrada legacy puede observar Windows; nunca autoriza captura por igualdad de datos.
        $composition = $script:GbComposition
        if (-not $composition) { throw 'GuestComponentsNotBound' }
        # Referencia privada admitida por composicion, nunca receipt/DTO del consumidor.
        $gate = if ($cleanup) { $owner.Gate } else { & $composition.Current $owner $AcquisitionRunId $Generation }
        Test-GbCurrent $owner $Generation $cleanup
        if (-not $gate -or -not [object]::ReferenceEquals($gate, $owner.Gate)) { throw 'CaptureGateMismatch' }
        if ($AcquisitionRunId -eq [guid]::Empty -or ($owner.Run -ne [guid]::Empty -and $owner.Run -ne $AcquisitionRunId)) { throw 'CaptureRunMismatch' }
        $owner.Run = $AcquisitionRunId
        if ($Operation -eq 'ConvertCapture' -and (-not $owner.StopObserved -or -not $owner.FileFinal)) { throw 'StopFinalizationRequired' }
        if ($Operation -eq 'CleanupCapture' -and $owner.StartSubmitted -and (-not $owner.StopObserved -or -not $owner.FileFinal)) { throw 'StopFinalizationRequired' }
        foreach ($step in $script:GbCaptureSteps[$Operation]) {
            if ($step -eq 'Start') { $owner.StartSubmitted = $true }
            $receipt = & $composition.Step $gate $step
            Test-GbCurrent $owner $Generation $cleanup
            if (@($receipt).Count -ne 1 -or $receipt.Phase -isnot [string] -or $receipt.Stop -isnot [string] -or $receipt.Cleanup -isnot [string] -or $receipt.Outcome -isnot [string]) { throw 'CaptureReceiptTypeInvalid' }
            if ($receipt.RunId -ne $AcquisitionRunId) { throw 'CaptureReceiptMismatch' }
            if ($receipt.Stop -cnotin @('Pending','Observed') -or $receipt.FileFinal -isnot [bool] -or $receipt.Cleanup -cnotin @('Pending','Observed','NotRequired')) { throw 'CaptureReceiptTypeInvalid' }
            if ($receipt.Outcome -cnotin @('NotStarted','CaptureStarted','Invalid','ConfigFailed/NotStarted') -or $receipt.CreateSubmitted -isnot [bool] -or $receipt.StartSubmitted -isnot [bool] -or $receipt.StartSubmitted -ne $owner.StartSubmitted) { throw 'CaptureOutcomeInvalid' }
            # Validar el recibo completo antes de mutar observaciones o liberar el Gate propio.
            if ($receipt.Phase -cnotin $script:GbCapturePhases[$step]) { throw 'CaptureReceiptMismatch' }
            if (-not $cleanup -and $receipt.Outcome -cin @('Invalid','ConfigFailed/NotStarted')) { throw 'CaptureOutcomeInvalid' }
            if ($receipt.Phase -ceq 'Removed' -and $receipt.Cleanup -ceq 'Observed' -and (-not $owner.StartSubmitted -or ($owner.StopObserved -and $owner.FileFinal))) { $owner.Gate = $null }
            if ($step -eq 'Stop') { $owner.StopObserved = $receipt.Stop -ceq 'Observed'; $owner.FileFinal = $receipt.FileFinal }
            if ($step -eq 'Convert') {
                if ($receipt.ConversionPending -isnot [bool] -or $receipt.ConversionPending -or
                    -not $receipt.Conversion -or $receipt.Conversion.Outcome -cne 'ConvertedOriginalLengthUnknown') { throw 'ConversionUnconfirmed' }
                $owner.Conversion=$receipt.Conversion
            }
            if ($step -eq 'Cleanup' -and $receipt.Cleanup -ceq 'Observed') { $owner.Gate = $null }
            if ($step -eq 'Cleanup' -and $receipt.Cleanup -ceq 'NotRequired' -and $receipt.Phase -ceq 'NoResources' -and -not $receipt.CreateSubmitted -and -not $owner.StartSubmitted) { $owner.Gate = $null }
        }
        Get-GbView $owner
    } catch {
        if ($_.Exception.Message -ne 'GuestComponentsNotBound') { Set-GbInvalid $owner 'CommandUnconfirmed' }
        throw
    } finally { $owner.Busy = $false }
}
function Open-GbOwnEnrollmentSupervisor($enrollment,[string]$local,[string]$peer) {
    if (-not $enrollment -or -not $enrollment.Issuer -or $enrollment.Supervisor) { throw 'EnrollmentBindingInvalid' }
    & $enrollment.Issuer { param($bound) Confirm-VmGuestEnrollmentOwn $bound } $enrollment
    $source=$enrollment.Owner; $channel=$enrollment.Channel; $sample=$enrollment.AuthenticatedObservation
    if ($channel.Session -isnot [System.Management.Automation.Runspaces.PSSession] -or
        -not [object]::ReferenceEquals($source.GuestEnrollment,$enrollment)) { throw 'EnrollmentBindingInvalid' }
    if (@($script:GbOwners.Values | Where-Object { $_.VmId -eq $source.VmId -and $_.State -ne 'Closed' }).Count) { throw 'VmOwnershipPending' }
    $now=& $script:GbClock
    $owner=@{Id=[guid]::NewGuid();VmId=$source.VmId;LabId=$source.Id;Instance=$channel.Instance;Session=$channel.Session;
        Resources=[Collections.Generic.List[object]]::new();Inventory=$null;Nic=$null;Gate=$null;Run=[guid]::Empty;
        Boot=$sample.Boot;Nonce='';Plan=@{Hash=$enrollment.Package.Hashes[2];Mac=$sample.Mac;Sid=$sample.Sid};
        State='CreatingWindows';Cause='';Created=$now;Observed=$now;Deadline=$now+10000;Generation=[long]0;
        Revoked=$false;Busy=$true;CleanupPending=$true;StartSubmitted=$false;StopObserved=$false;FileFinal=$false;
        CapturePackage=$null;CaptureLocal=$local;CapturePeer=$peer;CaptureCancel=[Threading.CancellationTokenSource]::new();
        Conversion=$null;Enrollment=$enrollment}
    # Ambas reservas preceden cualquier callback; el módulo no exporta este constructor.
    $script:GbOwners[$owner.Id]=$owner; $enrollment.Supervisor=$owner
    $owner.Resources.Add(@{Session=$channel.Session;Pending=$true})
    try {
        Confirm-GbEnrollmentOwn $owner
        $owner.Inventory=& $script:GbInventory $owner.VmId
        Confirm-GbBootstrap $owner $owner.Generation
        $owner.Deadline=$now+60000; $owner.State='WindowsEnrolled'; $owner.Cause='BrokerNoJobNotObserved'
    } catch { Set-GbInvalid $owner 'EnrollmentBindingUnconfirmed'; throw }
    finally { $owner.Busy=$false }
    Get-GbView $owner
}
function Close-GbOwnEnrollmentSupervisor($enrollment) {
    $owner=$enrollment.Supervisor
    if (-not $owner -or -not [object]::ReferenceEquals((Get-GbOwner $owner.Id),$owner) -or
        -not [object]::ReferenceEquals($owner.Enrollment,$enrollment)) { throw 'EnrollmentBindingInvalid' }
    $null=Revoke-GbLabSupervisor $owner.Id
    if ($owner.Busy) { throw 'PipelineBusy' }
    if ($owner.Gate) {
        if ($owner.StartSubmitted -and (-not $owner.StopObserved -or -not $owner.FileFinal)) {
            $null=Invoke-GbLabCommand $owner.Id $owner.Generation $owner.Run 'StopCapture'
        }
        $null=Invoke-GbLabCommand $owner.Id $owner.Generation $owner.Run 'CleanupCapture'
    }
    Close-GbOwnResource $owner
    Get-GbView $owner
}
function Revoke-GbLabSupervisor {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    $owner = Get-GbOwner $OwnerId
    $owner.CaptureCancel.Cancel()
    if (-not $owner.Revoked) {
        if ($owner.Generation -lt [long]::MaxValue) { $owner.Generation++ }
        Set-GbInvalid $owner 'Cancelled'
    }
    if ($owner.Gate -and $script:GbComposition -and -not $owner.Busy) {
        $owner.Busy = $true
        try {
            Test-GbCurrent $owner $owner.Generation $true
            $null = & $script:GbComposition.Step $owner.Gate 'Cancel'
            # Cancel solicitado no es parada kernel ni cleanup observado.
        } catch { $owner.Cause = 'CancelUnconfirmed'; $owner.CleanupPending = $true }
        finally { $owner.Busy = $false }
    }
    # Un canal ocupado/perdido conserva cuarentena; no Stop paralelo ni otro canal.
    Get-GbView $owner
}
function Close-GbLabSupervisor {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    $owner = Get-GbOwner $OwnerId
    $null = Revoke-GbLabSupervisor $OwnerId
    Close-GbOwnResource $owner
    Get-GbView $owner
}
Export-ModuleMember -Function Open-GbWindowsSupervisor,Get-GbLabSupervisorState,Invoke-GbLabCommand,Revoke-GbLabSupervisor,Close-GbLabSupervisor
