Set-StrictMode -Version Latest
# Datos puros: esta unidad no crea procesos ni autentica endpoints.
$script:GbBootstrapKeys = @('v','kind','request','boot','uid','pid','start','bundle','ifindex','mac','ip')
$script:GbTerminalKeys = @('v','kind','request','boot','pid','start','operation','exit','cleanup')

function Get-GbCanonicalRecord([string]$Line,[string[]]$Keys,[string]$Kind) {
    $document = $null
    try {
        $document = [System.Text.Json.JsonDocument]::Parse($Line)
        $root = $document.RootElement
        if ($root.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { throw 'RecordShapeInvalid' }
        $properties = @($root.EnumerateObject())
        if ($properties.Count -ne $Keys.Count) { throw 'RecordFieldsInvalid' }
        $values = @{}
        $parts = [Collections.Generic.List[string]]::new()
        for ($i=0; $i -lt $Keys.Count; $i++) {
            $property = $properties[$i]
            if ($property.Name -cne $Keys[$i]) { throw 'RecordFieldsInvalid' }
            if ($i -eq 0) {
                if ($property.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::Number -or $property.Value.GetRawText() -cne '1') { throw 'RecordVersionInvalid' }
                $parts.Add('"v":1')
            } else {
                if ($property.Value.ValueKind -ne [System.Text.Json.JsonValueKind]::String) { throw 'RecordTypeInvalid' }
                $value = $property.Value.GetString()
                if ($value -cnotmatch '^[A-Za-z0-9.:]+$') { throw 'RecordCharactersInvalid' }
                $values[$property.Name] = $value
                $parts.Add('"'+$property.Name+'":"'+$value+'"')
            }
        }
        if ($values.kind -cne $Kind -or ('{'+($parts -join ',')+'}') -cne $Line) { throw 'RecordCanonicalInvalid' }
        $values
    } catch {
        if ($_.Exception.Message -like 'Record*') { throw }
        throw 'RecordJsonInvalid'
    } finally { if ($document) { $document.Dispose() } }
}
function Test-GbDecimal([string]$Value,[uint64]$Minimum,[uint64]$Maximum) {
    $number = [uint64]0
    if ($Value -cnotmatch '^(0|[1-9][0-9]{0,19})$' -or -not [uint64]::TryParse($Value,[ref]$number) -or $number -lt $Minimum -or $number -gt $Maximum) { throw 'RecordDecimalInvalid' }
}
function Test-GbHex([string]$Value,[int]$Length,[bool]$Upper,[bool]$NoZero) {
    $alphabet = if ($Upper) { '0-9A-F' } else { '0-9a-f' }
    if ($Value -cnotmatch ('^['+$alphabet+']{'+$Length+'}$') -or ($NoZero -and $Value -eq ('0'*$Length))) { throw 'RecordHexInvalid' }
}
function Test-GbCanonicalIp([string]$Value) {
    $address = $null
    if (-not [Net.IPAddress]::TryParse($Value,[ref]$address) -or $address.ToString() -cne $Value -or $Value.Contains('%')) { throw 'RecordIpInvalid' }
}
function ConvertFrom-GbLinuxBootstrapPair {
    [CmdletBinding()]
    param([Parameter(Mandatory)][byte[]]$Bytes,
        [Parameter(Mandatory)][int]$ExitCode,[Parameter(Mandatory)][bool]$EndOfStream,
        [Parameter(Mandatory)][hashtable]$Expected,[byte[]]$Stderr = @())
    if ($Bytes.Length -gt 2048 -or $Stderr.Length -gt 4096) { throw 'OutputLimitExceeded' }
    if (-not $EndOfStream -or $ExitCode -ne 0) { throw 'TransportTerminalInvalid' }
    $required = @('Request','Boot','Uid','Bundle','InterfaceIndex','Mac','Ip','OwnProcess','CurrentProcess','Generation','CurrentGeneration','Cancelled','LeaseCurrent','TopologyCurrent')
    if ($Expected.Count -ne $required.Count) { throw 'BindingFieldsInvalid' }
    foreach ($key in $required) { if (-not $Expected.ContainsKey($key)) { throw 'BindingFieldsInvalid' } }
    # Identidad por referencia para correlacionar datos; no prueba que Process haya arrancado.
    if ($Expected.OwnProcess -isnot [Diagnostics.Process] -or -not [object]::ReferenceEquals($Expected.OwnProcess,$Expected.CurrentProcess)) { throw 'BindingReferenceInvalid' }
    if ($Expected.Generation -isnot [long] -or $Expected.CurrentGeneration -isnot [long] -or $Expected.Generation -lt 0 -or $Expected.Generation -ne $Expected.CurrentGeneration) { throw 'BindingGenerationInvalid' }
    if ($Expected.Cancelled -isnot [bool] -or $Expected.LeaseCurrent -isnot [bool] -or $Expected.TopologyCurrent -isnot [bool] -or $Expected.Cancelled -or -not $Expected.LeaseCurrent -or -not $Expected.TopologyCurrent) { throw 'BindingRevoked' }
    foreach ($key in @('Request','Boot','Uid','Bundle','InterfaceIndex','Mac','Ip')) { if ($Expected[$key] -isnot [string]) { throw 'BindingTypeInvalid' } }
    foreach ($byte in $Bytes) { if ($byte -gt 127 -or ($byte -lt 32 -and $byte -ne 10)) { throw 'StreamCharactersInvalid' } }
    $text = [Text.Encoding]::ASCII.GetString($Bytes)
    $lines = @($text -split "`n")
    if ($lines.Count -ne 3 -or $lines[2] -cne '' -or $lines[0].Length -gt 1023 -or $lines[1].Length -gt 1023) { throw 'StreamFramingInvalid' }
    $bootstrap = Get-GbCanonicalRecord $lines[0] $script:GbBootstrapKeys 'Bootstrap'
    $terminal = Get-GbCanonicalRecord $lines[1] $script:GbTerminalKeys 'Terminal'
    foreach ($record in @($bootstrap,$terminal)) {
        Test-GbHex $record.request 32 $false $true
        Test-GbHex $record.boot 32 $false $true
        Test-GbDecimal $record.pid 1 2147483647
        Test-GbDecimal $record.start 1 ([uint64]::MaxValue)
    }
    Test-GbHex $bootstrap.bundle 64 $true $false
    Test-GbHex $bootstrap.mac 12 $true $false
    Test-GbDecimal $bootstrap.uid 0 2147483647
    Test-GbDecimal $bootstrap.ifindex 1 2147483647
    Test-GbDecimal $terminal.exit 0 254
    Test-GbCanonicalIp $bootstrap.ip
    $map = @{Request='request';Boot='boot';Uid='uid';Bundle='bundle';InterfaceIndex='ifindex';Mac='mac';Ip='ip'}
    foreach ($key in $map.Keys) { if ($bootstrap[$map[$key]] -cne $Expected[$key]) { throw 'BindingObservationMismatch' } }
    foreach ($key in @('request','boot','pid','start')) { if ($bootstrap[$key] -cne $terminal[$key]) { throw 'TerminalCorrelationMismatch' } }
    if ($terminal.operation -cne 'bootstrap' -or $terminal.cleanup -cne 'NoResources' -or $terminal.exit -cne '0') { throw 'TerminalObservationInvalid' }
    [pscustomobject]@{ProjectionStatus='ValidatedData';Request=$bootstrap.request;Boot=$bootstrap.boot;
        Uid=$bootstrap.uid;Pid=$bootstrap.pid;StartTicks=$bootstrap.start;Bundle=$bootstrap.bundle;
        InterfaceIndex=$bootstrap.ifindex;Mac=$bootstrap.mac;Ip=$bootstrap.ip;CleanupObservation='NoResources';
        TransportAuthentication='NotEstablishedByParser';StderrBytes=$Stderr.Length}
}

function Get-GbLinuxConfigBytes([string]$Ip,[string]$Alias,[int]$Port) {
    Test-GbCanonicalIp $Ip
    if ($Alias -cnotmatch '^[a-z0-9-]{1,64}$' -or $Port -lt 1 -or $Port -gt 65535) { throw 'ConfigProfileInvalid' }
    $lines = @(
        ('Host '+$Ip),('    HostName '+$Ip),('    HostKeyAlias '+$Alias),
        '    User gatebouncerlab',('    Port '+$Port),
        '    IdentityFile C:/GateBouncerLab/ssh/lab_identity',
        '    IdentitiesOnly yes','    IdentityAgent none','    CertificateFile none',
        '    PKCS11Provider none','    SecurityKeyProvider none',
        '    StrictHostKeyChecking yes','    UserKnownHostsFile C:/GateBouncerLab/ssh/lab_known_hosts',
        '    GlobalKnownHostsFile none','    KnownHostsCommand none','    UpdateHostKeys no',
        '    VerifyHostKeyDNS no','    BatchMode yes','    PreferredAuthentications publickey',
        '    PasswordAuthentication no','    KbdInteractiveAuthentication no',
        '    HostbasedAuthentication no','    GSSAPIAuthentication no',
        '    PermitLocalCommand no','    LocalCommand none','    ProxyCommand none','    ProxyJump none',
        '    ControlMaster no','    ControlPath none','    ControlPersist no',
        '    ForwardAgent no','    ForwardX11 no','    ClearAllForwardings yes','    RequestTTY no',
        '    ConnectionAttempts 1','    ConnectTimeout 5')
    ,([Text.Encoding]::ASCII.GetBytes(($lines -join "`n")+"`n"))
}
function Compare-GbLinuxBytes([byte[]]$Left,[byte[]]$Right) {
    if ($Left.Length -ne $Right.Length) { throw 'ClosureBytesMismatch' }
    for ($i=0; $i -lt $Left.Length; $i++) { if ($Left[$i] -ne $Right[$i]) { throw 'ClosureBytesMismatch' } }
}
function Compare-GbLinuxClosureSnapshot([hashtable]$Expected,[hashtable]$Observed) {
    # Comparacion privada pura de observaciones; no sustituye locks/enrollment/Guard nativo.
    $keys = @('Ip','Alias','Port','ExecutablePath','ExecutableHash','ExecutableFileId','ConfigBytes','ConfigFileId',
        'KnownHostsBytes','KnownHostsFileId','KeyIdentity','RemoteProfileHash','Environment')
    foreach ($item in @($Expected,$Observed)) {
        if ($item.Count -ne $keys.Count) { throw 'ClosureFieldsInvalid' }
        foreach ($key in $keys) { if (-not $item.ContainsKey($key)) { throw 'ClosureFieldsInvalid' } }
        foreach ($key in @('Ip','Alias','ExecutablePath','ExecutableHash','ExecutableFileId','ConfigFileId','KnownHostsFileId','KeyIdentity','RemoteProfileHash')) {
            if ($item[$key] -isnot [string] -or -not $item[$key] -or $item[$key].Length -gt 256) { throw 'ClosureTypeInvalid' }
        }
        if ($item.Port -isnot [int] -or $item.ConfigBytes -isnot [byte[]] -or $item.KnownHostsBytes -isnot [byte[]] -or $item.Environment -isnot [hashtable]) { throw 'ClosureTypeInvalid' }
        if ($item.ExecutablePath -cne 'C:\Windows\System32\OpenSSH\ssh.exe') { throw 'ExecutablePathInvalid' }
        Test-GbHex $item.ExecutableHash 64 $true $false
        Test-GbHex $item.RemoteProfileHash 64 $true $false
        if ($item.ConfigBytes.Length -gt 4096 -or $item.KnownHostsBytes.Length -gt 4096) { throw 'ClosureLimitExceeded' }
        $fixed = Get-GbLinuxConfigBytes $item.Ip $item.Alias $item.Port
        Compare-GbLinuxBytes $fixed $item.ConfigBytes
        if ($item.KnownHostsBytes.Length -eq 0) { throw 'KnownHostsEmpty' }
        foreach ($byte in $item.KnownHostsBytes) { if ($byte -gt 127 -or ($byte -lt 32 -and $byte -ne 10)) { throw 'KnownHostsShapeInvalid' } }
        $pinLines = @([Text.Encoding]::ASCII.GetString($item.KnownHostsBytes) -split "`n")
        if ($pinLines.Count -ne 2 -or $pinLines[1] -cne '' -or $pinLines[0] -cnotmatch '^[A-Za-z0-9.:[\]-]+ (ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256) [A-Za-z0-9+/]+={0,2}$') { throw 'KnownHostsShapeInvalid' }
        # Unico pin ya enrolado: igualdad exacta de bytes; no valida la clave criptografica.
        $envKeys = @('SystemRoot','WINDIR','TEMP','TMP')
        if ($item.Environment.Count -ne 4) { throw 'EnvironmentClosureInvalid' }
        foreach ($key in $envKeys) {
            if (-not $item.Environment.ContainsKey($key) -or $item.Environment[$key] -isnot [string]) { throw 'EnvironmentClosureInvalid' }
        }
        if ($item.Environment.SystemRoot -cne 'C:\Windows' -or $item.Environment.WINDIR -cne 'C:\Windows' -or
            $item.Environment.TEMP -cnotmatch '^C:\\GateBouncerLab\\tmp\\[0-9a-f]{32}$' -or $item.Environment.TMP -cne $item.Environment.TEMP) { throw 'EnvironmentClosureInvalid' }
    }
    foreach ($key in $keys) {
        switch ($key) {
            {$_ -in @('ConfigBytes','KnownHostsBytes')} { Compare-GbLinuxBytes $Expected[$key] $Observed[$key] }
            'Environment' {
                foreach ($name in @('SystemRoot','WINDIR','TEMP','TMP')) { if ($Expected.Environment[$name] -cne $Observed.Environment[$name]) { throw 'EnvironmentClosureMismatch' } }
            }
            default { if ($Expected[$key] -cne $Observed[$key]) { throw 'ClosureIdentityMismatch' } }
        }
    }
    'ClosureDataMatched'
}
Export-ModuleMember -Function ConvertFrom-GbLinuxBootstrapPair
