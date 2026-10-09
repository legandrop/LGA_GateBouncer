# Adaptadores privados del mismo owner. Importar nunca abre medios ni invoca Hyper-V.
$script:VmIsoPath=Join-Path $script:VmRoot 'media\ubuntu-24.04.5-live-server-amd64.iso'
$script:VmIsoHash='97F3D7FFB032C3EB3B23D2C8BE9CC76E60C2C1F2C0146BA5BA9FE01CAFAE0FD8'
$script:VmIsoBytes=[long]4080486400
$script:VmDiskBytes=[long]68719476736
$script:VmVhdType={ param($value) $null -ne $value -and $value.GetType().FullName -ceq 'Microsoft.Vhd.PowerShell.VirtualHardDisk' }
$script:VmFilePathCheck={
    param([string]$target,[bool]$mustExist)
    $path=[IO.Path]::GetFullPath($target)
    if (-not $path.StartsWith($script:VmRoot.TrimEnd('\')+'\',[StringComparison]::OrdinalIgnoreCase)) { throw 'FileOutsideBoundary' }
    if ((Test-Path -LiteralPath $path -ErrorAction Stop) -ne $mustExist) { throw 'FileExistenceChanged' }
    if ($mustExist) {
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'FileCustodyUnconfirmed' }
    }
    $path=[IO.Path]::GetDirectoryName($path)
    while ($path) {
        $entry=Get-Item -LiteralPath $path -ErrorAction Stop
        if (-not $entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'FileCustodyUnconfirmed' }
        $path=[IO.Path]::GetDirectoryName($entry.FullName.TrimEnd('\'))
    }
}
$script:VmIsoOpen={ [IO.FileStream]::new($script:VmIsoPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read) }
$script:VmIsoInspect={
    param($stream)
    if ($stream -isnot [IO.FileStream] -or -not $stream.CanRead -or -not $stream.CanSeek -or $stream.CanWrite -or
        -not $stream.Name.Equals($script:VmIsoPath,[StringComparison]::OrdinalIgnoreCase)) { throw 'IsoStreamInvalid' }
    $stream.Position=0
    $sha=[Security.Cryptography.SHA256]::Create()
    try { $hash=([BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-','') }
    finally { $sha.Dispose() }
    if ($stream.Length -ne $script:VmIsoBytes -or $hash -cne $script:VmIsoHash) { throw 'IsoPinChanged' }
    $stream.Position=0
}
$script:VmDiskOpen={ param($path) [IO.FileStream]::new($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite) }
$script:VmDiskInspect={
    param($stream,$path)
    if ($stream -isnot [IO.FileStream] -or -not $stream.CanRead -or -not $stream.Name.Equals($path,[StringComparison]::OrdinalIgnoreCase)) { throw 'DiskStreamInvalid' }
}
$script:VmNewVhd={ param($path) Hyper-V\New-VHD -Path $path -Dynamic -SizeBytes 68719476736 -ErrorAction Stop }
$script:VmGetVhd={ param($path) Hyper-V\Get-VHD -Path $path -ErrorAction Stop }
$script:VmAddDisk={ param($vm,$path) Hyper-V\Add-VMHardDiskDrive -VM $vm -Path $path -ControllerType SCSI -ControllerNumber 0 -ControllerLocation 0 -Passthru -ErrorAction Stop }
$script:VmAddDvd={ param($vm) Hyper-V\Add-VMDvdDrive -VM $vm -Path $script:VmIsoPath -ControllerNumber 0 -ControllerLocation 1 -Passthru -ErrorAction Stop }
$script:VmDvds={ param($vm) @(Hyper-V\Get-VMDvdDrive -VM $vm -ErrorAction Stop) }
$script:VmSetFirmware={ param($vm,$dvd,$disk) Hyper-V\Set-VMFirmware -VM $vm -EnableSecureBoot On -SecureBootTemplate MicrosoftUEFICertificateAuthority -BootOrder @($dvd,$disk) -ErrorAction Stop }
$script:VmFirmware={ param($vm) Hyper-V\Get-VMFirmware -VM $vm -ErrorAction Stop }
$script:VmStart={ param($vm) Hyper-V\Start-VM -VM $vm -ErrorAction Stop }

function Test-VmStorageAttemptFrame($frame) {
    $storage=$frame.Owner.Storage
    # Excepción sólo para la llamada en curso; nunca basta un nombre de estado.
    $script:VmBoundary.Busy -and $storage -and $storage.Attempt -and $storage.Attempt.Active -and
        $frame.Attempt -and [object]::ReferenceEquals($frame.Attempt,$storage.Attempt) -and
        [object]::ReferenceEquals($frame,$script:VmBoundary.Frame) -and
        [object]::ReferenceEquals($frame.Owner,$storage.Owner)
}
function Begin-VmStorageAttempt($owner,[string]$operation) {
    $storage=$owner.Storage
    if ($storage.Attempts.ContainsKey($operation)) { throw 'StorageReplayRejected' }
    $attempt=@{Operation=$operation;Submitted=$false;Active=$false;Outputs=[Collections.Generic.List[object]]::new()}
    $storage.Attempts[$operation]=$attempt; $storage.Attempt=$attempt
    Write-VmOwnIntent $owner $operation
    $attempt.Active=$true; $script:VmBoundary.Frame.Attempt=$attempt
    $attempt.Submitted=$true; $script:VmBoundary.UnknownEffect=$true
    Test-VmOwnFrame
    $attempt
}
function Complete-VmStorageAttempt($owner) {
    Test-VmOwnFrame
    $script:VmBoundary.UnknownEffect=$false
    $owner.Storage.Attempt.Active=$false; $script:VmBoundary.Frame.Attempt=$null
    Test-VmOwnFrame
}
function Read-VmStorageSingle($owner,[scriptblock]$port,[object[]]$arguments) {
    $attempt=$owner.Storage.Attempt
    & $port @arguments | ForEach-Object { $attempt.Outputs.Add($_) }
    Test-VmOwnFrame
    if ($attempt.Outputs.Count -ne 1) { throw 'StorageReturnCardinality' }
    $attempt.Outputs[0]
}
function Confirm-VmVhdOwn($owner) {
    $storage=$owner.Storage
    Read-VmOwnPort $script:VmFilePathCheck @($storage.Path,$true) | Out-Null
    $values=@(Read-VmOwnPort $script:VmGetVhd @($storage.Path))
    if ($values.Count -ne 1 -or -not (& $script:VmVhdType $values[0]) -or -not $storage.Disk) { throw 'VhdObservationUnconfirmed' }
    foreach ($disk in @($storage.Disk,$values[0])) {
        if (-not (& $script:VmVhdType $disk) -or [string]$disk.VhdFormat -cne 'VHDX' -or [string]$disk.VhdType -cne 'Dynamic' -or
            [long]$disk.Size -ne $script:VmDiskBytes -or -not [string]::IsNullOrEmpty([string]$disk.ParentPath) -or
            -not ([string]$disk.Path).Equals($storage.Path,[StringComparison]::OrdinalIgnoreCase) -or
            [guid]$disk.DiskIdentifier -eq [guid]::Empty -or [guid]$disk.DiskIdentifier -ne [guid]$storage.Disk.DiskIdentifier) { throw 'VhdChanged' }
    }
    if ($storage.DiskStreams.Count -ne 1) { throw 'DiskCustodyUnconfirmed' }
    Read-VmOwnPort $script:VmDiskInspect @($storage.DiskStreams[0],$storage.Path) | Out-Null
}
function Confirm-VmDeviceOwn($owner,$device,[string]$kind,[int]$location,[string]$path,$original) {
    if (-not (& $script:VmType $device $kind) -or -not (& $script:VmType $original $kind) -or
        [guid]$device.VMId -ne $owner.VmId -or [guid]$original.VMId -ne $owner.VmId -or
        [string]$device.ControllerType -cne 'SCSI' -or [int]$device.ControllerNumber -ne 0 -or [int]$device.ControllerLocation -ne $location -or
        ([string]$device.Id).Length -eq 0 -or [string]$device.Id -cne [string]$original.Id -or
        -not ([string]$device.Path).Equals($path,[StringComparison]::OrdinalIgnoreCase) -or
        -not ([string]$original.Path).Equals($path,[StringComparison]::OrdinalIgnoreCase)) { throw 'StorageDeviceChanged' }
}
function Confirm-VmAttachmentsOwn($owner,[bool]$dvdRequired) {
    $storage=$owner.Storage; $vm=$owner.Resources[0].Ref
    $disks=@(Read-VmOwnPort $script:VmDisks @($vm))
    if ($disks.Count -ne 1) { throw 'DiskAttachmentCardinality' }
    Confirm-VmDeviceOwn $owner $disks[0] 'HardDiskDrive' 0 $storage.Path $storage.Attachment
    $dvds=@(Read-VmOwnPort $script:VmDvds @($vm))
    if ($dvdRequired) {
        if ($dvds.Count -ne 1) { throw 'DvdCardinality' }
        Confirm-VmDeviceOwn $owner $dvds[0] 'DvdDrive' 1 $script:VmIsoPath $storage.Dvd
    } elseif ($dvds.Count -ne 0) { throw 'DvdUnexpected' }
}
function Confirm-VmFirmwareOwn($owner) {
    $storage=$owner.Storage
    $values=@(Read-VmOwnPort $script:VmFirmware @($owner.Resources[0].Ref))
    if ($values.Count -ne 1 -or -not (& $script:VmType $values[0] 'VMFirmware')) { throw 'FirmwareObservationUnconfirmed' }
    $firmware=$values[0]
    if ([string]$firmware.SecureBoot -cne 'On' -or [string]$firmware.SecureBootTemplate -cne 'MicrosoftUEFICertificateAuthority') { throw 'FirmwareChanged' }
    $order=@($firmware.BootOrder)
    if ($order.Count -ne 2) { throw 'BootOrderChanged' }
    for ($i=0;$i -lt 2;$i++) {
        $device=$order[$i]
        if (& $script:VmType $device 'VMBootSource') {
            if (-not $device.PSObject.Properties['Device']) { throw 'BootRepresentationUnsupported' }
            $device=$device.Device
        }
        if ($i -eq 0) { Confirm-VmDeviceOwn $owner $device 'DvdDrive' 1 $script:VmIsoPath $storage.Dvd }
        else { Confirm-VmDeviceOwn $owner $device 'HardDiskDrive' 0 $storage.Path $storage.Attachment }
    }
}
function Confirm-VmStorageOwn($owner,$vm) {
    $storage=$owner.Storage
    if (-not [object]::ReferenceEquals($storage.Owner,$owner)) { throw 'StorageNotPrepared' }
    if ($storage.Phase -ceq 'Preparing') {
        $frame=$script:VmBoundary.Frame
        if (-not $script:VmBoundary.Busy -or -not $frame -or
            -not [object]::ReferenceEquals($frame.Owner,$owner) -or
            -not [object]::ReferenceEquals($frame.PreparingStorage,$storage) -or [string]$vm.State -cne 'Off') { throw 'StorageNotPrepared' }
        Confirm-VmVhdOwn $owner
        if ($storage.Stage -ceq 'DiskCreated') {
            if (@(Read-VmOwnPort $script:VmDisks @($owner.Resources[0].Ref)).Count -ne 0 -or
                @(Read-VmOwnPort $script:VmDvds @($owner.Resources[0].Ref)).Count -ne 0) { throw 'StoragePreexisting' }
        } elseif ($storage.Stage -ceq 'DiskAttached') { Confirm-VmAttachmentsOwn $owner $false }
        elseif ($storage.Stage -cin @('DvdAttached','FirmwareSet')) {
            Confirm-VmAttachmentsOwn $owner $true
            if ($storage.Stage -ceq 'FirmwareSet') { Confirm-VmFirmwareOwn $owner }
        } else { throw 'StorageStageUnconfirmed' }
        return
    }
    if ($storage.Phase -cnotin @('PreparedOff','BootSubmitted','BootRunning')) { throw 'StorageNotPrepared' }
    $bootTicks=[long]0
    if ($storage.Phase -ceq 'PreparedOff') {
        if ([string]$vm.State -cne 'Off') { throw 'VmUnexpectedBoot' }
    } else {
        $bootTicks=[long]$vm.Uptime.Ticks
        if (-not $storage.StartSubmitted -or [string]$vm.State -cne 'Running' -or $bootTicks -le 0 -or
            $bootTicks -lt $storage.Uptime) { throw 'VmBootObservationChanged' }
    }
    if ($storage.IsoStreams.Count -ne 1) { throw 'IsoCustodyUnconfirmed' }
    Read-VmOwnPort $script:VmFilePathCheck @($script:VmIsoPath,$true) | Out-Null
    # El hash completo se hace al adquirir; Share.Read conserva esa imagen del medio.
    if (-not $storage.IsoStreams[0].CanRead) { throw 'IsoCustodyUnconfirmed' }
    Confirm-VmVhdOwn $owner
    Confirm-VmAttachmentsOwn $owner $true
    Confirm-VmFirmwareOwn $owner
    # Cada muestra causal conserva su valor monotónico, también durante el primer Start.
    if ($storage.Phase -cin @('BootSubmitted','BootRunning')) { $storage.Uptime=$bootTicks }
}
function Confirm-VmStoragePeers($owner) {
    Confirm-VmOwnMachine $owner
    foreach ($peer in $script:VmBoundary.Frame.Peers) { Confirm-VmOwnMachine $peer.Ref }
    Confirm-VmOwnSwitch
    Test-VmOwnFrame
}
function Prepare-GbOwnVmBoot {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    $owner=Get-VmOwnRecord $OwnerId
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    if ($owner.Kind -cne 'Linux') { throw 'WindowsMediaNotAdmitted' }
    if ($owner.Storage) { throw 'StorageReplayRejected' }
    $script:VmBoundary.Busy=$true
    try {
        Enter-VmOwnFrame $owner $false
        Test-VmOwnFrame
        Confirm-VmOwnMachine $owner
        Confirm-VmStoragePeers $owner
        # Reserva irreversible del camino storage antes de abrir o crear recursos.
        $storage=@{Owner=$owner;Phase='Preparing';Stage='Reserved';Path=(Join-Path $owner.Path 'system.vhdx');
            IsoStreams=[Collections.Generic.List[object]]::new();DiskStreams=[Collections.Generic.List[object]]::new();
            Attempts=@{};Attempt=$null;Disk=$null;Attachment=$null;Dvd=$null;StartSubmitted=$false;Uptime=[long]0}
        $owner.Storage=$storage; $owner.Pending=$true; $script:VmBoundary.Frame.PreparingStorage=$storage
        Read-VmOwnPort $script:VmFilePathCheck @($script:VmIsoPath,$true) | Out-Null
        & $script:VmIsoOpen | ForEach-Object { $storage.IsoStreams.Add($_) }
        Test-VmOwnFrame
        if ($storage.IsoStreams.Count -ne 1) { throw 'IsoCardinality' }
        Read-VmOwnPort $script:VmIsoInspect @($storage.IsoStreams[0]) | Out-Null
        Read-VmOwnPort $script:VmFilePathCheck @($storage.Path,$false) | Out-Null
        $null=Begin-VmStorageAttempt $owner 'CreateVhd'
        $storage.Disk=Read-VmStorageSingle $owner $script:VmNewVhd @($storage.Path)
        Read-VmOwnPort $script:VmFilePathCheck @($storage.Path,$true) | Out-Null
        & $script:VmDiskOpen $storage.Path | ForEach-Object { $storage.DiskStreams.Add($_) }
        Test-VmOwnFrame
        Confirm-VmVhdOwn $owner
        $storage.Stage='DiskCreated'
        Confirm-VmOwnMachine $owner
        Complete-VmStorageAttempt $owner
        Confirm-VmStoragePeers $owner
        # Ningún storage ajeno preexistente se acepta ni se retira.
        if (@(Read-VmOwnPort $script:VmDisks @($owner.Resources[0].Ref)).Count -ne 0 -or
            @(Read-VmOwnPort $script:VmDvds @($owner.Resources[0].Ref)).Count -ne 0) { throw 'StoragePreexisting' }
        $null=Begin-VmStorageAttempt $owner 'AttachDisk'
        $storage.Attachment=Read-VmStorageSingle $owner $script:VmAddDisk @($owner.Resources[0].Ref,$storage.Path)
        Confirm-VmAttachmentsOwn $owner $false
        Confirm-VmVhdOwn $owner
        $storage.Stage='DiskAttached'
        Confirm-VmOwnMachine $owner
        Complete-VmStorageAttempt $owner
        Confirm-VmStoragePeers $owner
        $null=Begin-VmStorageAttempt $owner 'AttachDvd'
        $storage.Dvd=Read-VmStorageSingle $owner $script:VmAddDvd @($owner.Resources[0].Ref)
        Confirm-VmAttachmentsOwn $owner $true
        Confirm-VmVhdOwn $owner
        $storage.Stage='DvdAttached'
        Confirm-VmOwnMachine $owner
        Complete-VmStorageAttempt $owner
        Confirm-VmStoragePeers $owner
        $null=Begin-VmStorageAttempt $owner 'SetFirmware'
        & $script:VmSetFirmware $owner.Resources[0].Ref $storage.Dvd $storage.Attachment | ForEach-Object { $storage.Attempt.Outputs.Add($_) }
        Test-VmOwnFrame
        Confirm-VmFirmwareOwn $owner
        Confirm-VmAttachmentsOwn $owner $true
        Confirm-VmVhdOwn $owner
        $storage.Stage='FirmwareSet'
        Confirm-VmOwnMachine $owner
        Complete-VmStorageAttempt $owner
        $storage.Phase='PreparedOff'
        Confirm-VmOwnMachine $owner
        Confirm-VmStoragePeers $owner
        $owner.Observed=Read-VmOwnClock
        Test-VmOwnFrame
        $owner.State='PreparedOff'; $owner.Cause='GuestBootEnrollmentMissing'
    } catch { Set-VmOwnRevoked $owner $_.Exception.Message }
    finally {
        if ($owner.Storage -and $owner.Storage.Attempt) { $owner.Storage.Attempt.Active=$false }
        $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false
    }
    Get-VmOwnView $owner
}
function Start-GbOwnVmBoot {
    [CmdletBinding()] param([Parameter(Mandatory)][guid]$OwnerId)
    $owner=Get-VmOwnRecord $OwnerId
    if ($script:VmBoundary.Busy) { throw 'ProvisioningBusy' }
    if ($owner.Kind -cne 'Linux') { throw 'WindowsMediaNotAdmitted' }
    if (-not $owner.Storage -or $owner.Storage.StartSubmitted -or $owner.Storage.Phase -cne 'PreparedOff') { throw 'BootReplayRejected' }
    $script:VmBoundary.Busy=$true
    try {
        Enter-VmOwnFrame $owner $false
        Test-VmOwnFrame
        Confirm-VmOwnMachine $owner
        Confirm-VmStoragePeers $owner
        $null=Begin-VmStorageAttempt $owner 'StartVm'
        $owner.Storage.StartSubmitted=$true; $owner.Storage.Phase='BootSubmitted'
        & $script:VmStart $owner.Resources[0].Ref | ForEach-Object { $owner.Storage.Attempt.Outputs.Add($_) }
        Test-VmOwnFrame
        Confirm-VmOwnMachine $owner
        Confirm-VmStoragePeers $owner
        Complete-VmStorageAttempt $owner
        # La lectura final usa el checker completo: esa misma muestra valida VM y storage.
        Confirm-VmStoragePeers $owner
        $owner.Storage.Phase='BootRunning'
        $owner.Observed=Read-VmOwnClock
        Test-VmOwnFrame
        $owner.State='BootRunning'; $owner.Cause='GuestBootEnrollmentMissing'
        # Running del host no autentica el boot, imagen instalada ni broker invitado.
    } catch { Set-VmOwnRevoked $owner $_.Exception.Message }
    finally {
        if ($owner.Storage -and $owner.Storage.Attempt) { $owner.Storage.Attempt.Active=$false }
        $script:VmBoundary.Frame=$null; $script:VmBoundary.Busy=$false
    }
    Get-VmOwnView $owner
}
