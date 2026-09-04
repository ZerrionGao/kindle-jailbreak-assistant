[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Action = "",

    [Parameter(Position = 1, ValueFromRemainingArguments = $true)]
    [string[]]$Arguments,

    [Parameter()]
    [string]$FixturePath = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$script:PortableDeviceInterfaceGuid = "{6ac27878-a6fa-4155-ba85-f98f491d4f33}"
$script:CopyFlags = 4 -bor 16 -bor 1024
$script:MinimumBytesPerSecond = 64 * 1024
$script:CopyOverheadSeconds = 15
$script:MaximumCopySeconds = 3600

function Write-Result([hashtable]$Payload) {
    [Console]::Out.WriteLine(($Payload | ConvertTo-Json -Compress -Depth 8))
}

function New-Outcome([hashtable]$Payload, [int]$ExitCode) {
    return [PSCustomObject]@{ Payload = $Payload; ExitCode = $ExitCode }
}

function New-Failure([string]$Code, [string]$Message, [hashtable]$Details = @{}) {
    $payload = @{
        ok = $false
        action = $Action
        error_code = $Code
        message = $Message
    }
    foreach ($entry in $Details.GetEnumerator()) {
        $payload[$entry.Key] = $entry.Value
    }
    return New-Outcome $payload 1
}

function Get-OpaqueId([string]$Value) {
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Value)
        $hash = $sha256.ComputeHash($bytes)
        return ([BitConverter]::ToString($hash).Replace("-", "").ToLowerInvariant()).Substring(0, 24)
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-IdentityToken([string]$InstanceId) {
    if ([string]::IsNullOrWhiteSpace($InstanceId)) {
        return ""
    }
    $leaf = @($InstanceId -split "[\\/]")[-1]
    $token = @($leaf -split "&")[0]
    return $token.Trim().ToUpperInvariant()
}

function Get-DeviceCode([string]$Identity) {
    $normalized = $Identity.Trim().ToUpperInvariant()
    if ($normalized.StartsWith("G") -and $normalized.Length -ge 6) {
        return $normalized.Substring(3, 3)
    }
    if ($normalized -match "^[0-9A-F]" -and $normalized.Length -ge 4) {
        return $normalized.Substring(2, 2)
    }
    return $null
}

function Get-NamedProperty($Object, [string]$Name) {
    if ($null -eq $Object) {
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    return $property.Value
}

function Get-ArrayProperty($Object, [string]$Name) {
    if ($null -eq $Object) {
        return ,@()
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return ,@()
    }
    return ,@($property.Value)
}

function Get-ExtendedProperty($Item, [string]$Name) {
    try {
        return $Item.ExtendedProperty($Name)
    }
    catch {
        return $null
    }
}

function Get-ChildItemByName($Folder, [string]$Name) {
    return @($Folder.Items()) |
        Where-Object {
            ([string]$_.Name).Normalize().ToUpperInvariant() -eq $Name.Normalize().ToUpperInvariant()
        } |
        Select-Object -First 1
}

function Test-LightweightPortableCandidate($Candidate) {
    if ($Candidate.IsFileSystem -ne $false) {
        return $false
    }
    if ($Candidate.InterfaceGuid.ToLowerInvariant() -ne $script:PortableDeviceInterfaceGuid) {
        return $false
    }
    if ($Candidate.Name -notmatch "(?i)kindle|amazon") {
        return $false
    }
    return -not [string]::IsNullOrEmpty((Get-IdentityToken $Candidate.InstanceId))
}

function Expand-ComCandidate($Candidate) {
    $deviceFolder = $Candidate.Source.GetFolder
    if ($null -eq $deviceFolder) {
        throw "portable device folder unavailable"
    }
    $storages = @()
    foreach ($storageItem in @($deviceFolder.Items())) {
        $hasDocuments = $false
        $storageFolder = $storageItem.GetFolder
        if ($null -ne $storageFolder) {
            $documents = Get-ChildItemByName $storageFolder "documents"
            $hasDocuments = $null -ne $documents -and $documents.IsFolder
        }
        $storages += [PSCustomObject]@{
            Name = [string]$storageItem.Name
            HasDocuments = $hasDocuments
            Source = $storageItem
        }
    }
    $Candidate.Storages = $storages
    return $Candidate
}

function Expand-FixtureCandidate($Candidate) {
    if ((Get-NamedProperty $Candidate.Source "expand_error") -eq $true) {
        throw "fixture candidate unavailable"
    }
    $storages = @()
    foreach ($storage in @($Candidate.Source.storages)) {
        $folders = Get-ArrayProperty $storage "folders"
        $storages += [PSCustomObject]@{
            Name = [string](Get-NamedProperty $storage "name")
            HasDocuments = $folders -ccontains "documents"
            Source = $storage
        }
    }
    $Candidate.Storages = $storages
    return $Candidate
}

function Expand-PortableCandidates([object[]]$Candidates, [string]$Backend) {
    $expanded = @()
    $expandedTags = @()
    $candidateErrors = 0
    foreach ($candidate in $Candidates) {
        if (-not (Test-LightweightPortableCandidate $candidate)) {
            continue
        }
        if ($Backend -eq "fixture") {
            $expandedTags += [string]$candidate.FixtureTag
        }
        try {
            $expandedCandidate = if ($Backend -eq "fixture") {
                Expand-FixtureCandidate $candidate
            }
            else {
                Expand-ComCandidate $candidate
            }
            $expanded += $expandedCandidate
        }
        catch {
            $candidateErrors += 1
        }
    }
    return [PSCustomObject]@{
        Candidates = $expanded
        Diagnostics = [PSCustomObject]@{
            ExpandedTags = $expandedTags
            CandidateErrors = $candidateErrors
        }
    }
}

function Get-ComCandidateBundle {
    $shell = New-Object -ComObject Shell.Application
    $computer = $shell.Namespace(17)
    if ($null -eq $computer) {
        throw "portable devices namespace unavailable"
    }

    $lightweightCandidates = @()
    foreach ($item in @($computer.Items())) {
        try {
            $lightweightCandidates += [PSCustomObject]@{
                Name = [string]$item.Name
                InterfaceGuid = [string](Get-ExtendedProperty $item "System.Devices.InterfaceClassGuid")
                InstanceId = [string](Get-ExtendedProperty $item "System.Devices.DeviceInstanceId")
                IsFileSystem = [bool]$item.IsFileSystem
                FixtureTag = ""
                Storages = @()
                Source = $item
            }
        }
        catch {
            continue
        }
    }
    $result = Expand-PortableCandidates $lightweightCandidates "com"
    return [PSCustomObject]@{
        Backend = "com"
        Candidates = $result.Candidates
        Diagnostics = $result.Diagnostics
        PollIntervalMs = 100
        MaximumPolls = 0
    }
}

function Get-FixtureCandidateBundle([string]$Path) {
    $fixture = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $lightweightCandidates = @()
    foreach ($item in @($fixture.devices)) {
        $lightweightCandidates += [PSCustomObject]@{
            Name = [string](Get-NamedProperty $item "name")
            InterfaceGuid = [string](Get-NamedProperty $item "interface_class_guid")
            InstanceId = [string](Get-NamedProperty $item "instance_id")
            IsFileSystem = [bool](Get-NamedProperty $item "is_file_system")
            FixtureTag = [string](Get-NamedProperty $item "fixture_tag")
            Storages = @()
            Source = $item
        }
    }
    $result = Expand-PortableCandidates $lightweightCandidates "fixture"
    return [PSCustomObject]@{
        Backend = "fixture"
        Candidates = $result.Candidates
        Diagnostics = $result.Diagnostics
        PollIntervalMs = [Math]::Max(0, [int](Get-NamedProperty $fixture "poll_interval_ms"))
        MaximumPolls = [Math]::Max(1, [int](Get-NamedProperty $fixture "max_polls"))
    }
}

function Select-KindleDevices($Bundle) {
    $devices = @()
    $seen = @{}
    foreach ($candidate in @($Bundle.Candidates)) {
        if (-not (Test-LightweightPortableCandidate $candidate)) {
            continue
        }
        $identity = Get-IdentityToken $candidate.InstanceId
        $validStorages = @($candidate.Storages | Where-Object { $_.HasDocuments -eq $true })
        if ($validStorages.Count -ne 1) {
            continue
        }
        $id = Get-OpaqueId $identity
        if ($seen.ContainsKey($id)) {
            continue
        }
        $seen[$id] = $true
        $devices += [PSCustomObject]@{
            Id = $id
            Identity = $identity
            DeviceCode = Get-DeviceCode $identity
            Name = $candidate.Name
            StorageName = $validStorages[0].Name
            Storage = $validStorages[0]
            Source = $candidate.Source
            Backend = $Bundle.Backend
            PollIntervalMs = $Bundle.PollIntervalMs
            MaximumPolls = $Bundle.MaximumPolls
        }
    }
    return $devices
}

function Resolve-Device([object[]]$Devices, [string]$DeviceId) {
    return $Devices | Where-Object { $_.Id -ceq $DeviceId } | Select-Object -First 1
}

function Get-SafeSegments([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or
        $Value.StartsWith("/") -or $Value.StartsWith("\")) {
        throw "invalid portable-device path"
    }
    $segments = @()
    foreach ($segment in ($Value.Replace("\", "/").Split("/"))) {
        if ([string]::IsNullOrEmpty($segment) -or $segment -eq ".") {
            continue
        }
        if ($segment -eq ".." -or $segment.Contains([char]0) -or $segment.Contains(":")) {
            throw "invalid portable-device path"
        }
        $segments += $segment
    }
    if ($segments.Count -eq 0) {
        throw "invalid portable-device path"
    }
    return $segments
}

function Resolve-ComMtpItem($RootItem, [string[]]$Segments) {
    $item = $RootItem
    foreach ($segment in $Segments) {
        $folder = $item.GetFolder
        if ($null -eq $folder) {
            return $null
        }
        $item = Get-ChildItemByName $folder $segment
        if ($null -eq $item) {
            return $null
        }
    }
    return $item
}

function Get-ComItemState($Item) {
    if ($null -eq $Item) {
        return [PSCustomObject]@{ Exists = $false; Size = $null; Source = $null }
    }
    $size = Get-ExtendedProperty $Item "System.Size"
    $normalizedSize = if ($null -eq $size) { $null } else { [Int64]$size }
    return [PSCustomObject]@{
        Exists = $true
        Size = $normalizedSize
        Source = $Item
    }
}

function Get-FixturePathState($Device, [string[]]$Segments, [string]$Direction, [int]$Poll) {
    $key = $Segments -join "/"
    if ($Direction -eq "probe") {
        $files = Get-NamedProperty $Device.Storage.Source "files"
        $size = Get-NamedProperty $files $key
        if ($null -ne $size) {
            return [PSCustomObject]@{ Exists = $true; Size = [Int64]$size; Source = $null }
        }
        $folders = @(Get-NamedProperty $Device.Storage.Source "folders")
        return [PSCustomObject]@{
            Exists = $folders -ccontains $key
            Size = $null
            Source = $null
        }
    }

    $collectionName = if ($Direction -eq "copy-to") { "copy_to" } else { "copy_from" }
    $collection = Get-NamedProperty $Device.Source $collectionName
    $behavior = Get-NamedProperty $collection $key
    $states = Get-ArrayProperty $behavior "states"
    if ($states.Count -eq 0) {
        throw "fixture transfer state unavailable"
    }
    $index = [Math]::Min([Math]::Max($Poll - 1, 0), $states.Count - 1)
    $size = $states[$index]
    $normalizedSize = if ($null -eq $size) { $null } else { [Int64]$size }
    return [PSCustomObject]@{
        Exists = $null -ne $size
        Size = $normalizedSize
        Source = $null
    }
}

function Get-PathState(
    $Device,
    [string[]]$Segments,
    [string]$Direction,
    [int]$Poll,
    [string]$LocalPath = ""
) {
    if ($Device.Backend -eq "fixture") {
        return Get-FixturePathState $Device $Segments $Direction $Poll
    }
    if ($Direction -eq "copy-from") {
        if (-not [System.IO.File]::Exists($LocalPath)) {
            return [PSCustomObject]@{ Exists = $false; Size = $null; Source = $null }
        }
        return [PSCustomObject]@{
            Exists = $true
            Size = ([System.IO.FileInfo]::new($LocalPath)).Length
            Source = $null
        }
    }
    $item = Resolve-ComMtpItem $Device.Storage.Source $Segments
    return Get-ComItemState $item
}

function Get-CopyTimeoutMilliseconds([Int64]$ExpectedSize) {
    $transferSeconds = [Math]::Ceiling(
        [double]$ExpectedSize / [double]$script:MinimumBytesPerSecond
    )
    $seconds = [Math]::Min(
        $script:MaximumCopySeconds,
        [Math]::Max($script:CopyOverheadSeconds, $script:CopyOverheadSeconds + $transferSeconds)
    )
    return [Int64]($seconds * 1000)
}

function Wait-RemoteItem(
    $Device,
    [string[]]$Segments,
    [Int64]$ExpectedSize,
    [string]$Direction,
    [string]$LocalPath = ""
) {
    $timeoutMs = Get-CopyTimeoutMilliseconds $ExpectedSize
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $poll = 0
    $sizes = @()
    $lastState = [PSCustomObject]@{ Exists = $false; Size = $null }
    while ($true) {
        $poll += 1
        $lastState = Get-PathState $Device $Segments $Direction $poll $LocalPath
        if ($lastState.Exists -and $null -ne $lastState.Size) {
            $sizes += [Int64]$lastState.Size
            if ([Int64]$lastState.Size -eq $ExpectedSize) {
                $null = $stopwatch.Stop()
                return [PSCustomObject]@{
                    Status = "complete"
                    Polls = $poll
                    TimeoutMs = $timeoutMs
                }
            }
        }

        $fixtureLimitReached = $Device.Backend -eq "fixture" -and $poll -ge $Device.MaximumPolls
        $timeLimitReached = $Device.Backend -ne "fixture" -and `
            $stopwatch.ElapsedMilliseconds -ge $timeoutMs
        if ($fixtureLimitReached -or $timeLimitReached) {
            break
        }
        if ($Device.PollIntervalMs -gt 0) {
            Start-Sleep -Milliseconds $Device.PollIntervalMs
        }
    }
    $null = $stopwatch.Stop()

    $growing = $sizes.Count -ge 2 -and $sizes[-1] -gt $sizes[-2]
    $status = if (
        $lastState.Exists -and $null -ne $lastState.Size -and
        [Int64]$lastState.Size -lt $ExpectedSize -and $growing
    ) { "copy_in_progress" } else { "failed" }
    return [PSCustomObject]@{
        Status = $status
        Polls = $poll
        TimeoutMs = $timeoutMs
    }
}

function Start-CopyTo($Device, [string[]]$Segments, [string]$Source) {
    if ($Device.Backend -eq "fixture") {
        $null = Get-FixturePathState $Device $Segments "copy-to" 1
        return
    }
    $parentSegments = @($Segments[0..([Math]::Max(0, $Segments.Count - 2))])
    if ($Segments.Count -eq 1) {
        $parentSegments = @()
    }
    $parentItem = Resolve-ComMtpItem $Device.Storage.Source $parentSegments
    if ($null -eq $parentItem) {
        throw "destination unavailable"
    }
    $null = $parentItem.GetFolder.CopyHere($Source, $script:CopyFlags)
}

function Start-CopyFrom($Device, $SourceItem, [string]$Destination) {
    if ($Device.Backend -eq "fixture") {
        $segments = @(Get-SafeSegments ([string](Get-NamedProperty $SourceItem "fixture_path")))
        $null = Get-FixturePathState $Device $segments "copy-from" 1
        return
    }
    $destinationDirectory = [System.IO.Path]::GetDirectoryName($Destination)
    $shell = New-Object -ComObject Shell.Application
    $targetFolder = $shell.Namespace($destinationDirectory)
    if ($null -eq $targetFolder) {
        throw "destination unavailable"
    }
    $null = $targetFolder.CopyHere($SourceItem, $script:CopyFlags)
}

function Get-FreeBytes($Device) {
    if ($Device.Backend -eq "fixture") {
        return Get-NamedProperty $Device.Storage.Source "free_bytes"
    }
    return Get-ExtendedProperty $Device.Storage.Source "System.FreeSpace"
}

function Get-DeviceFirmware($Device) {
    if ($Device.Backend -eq "fixture") {
        $value = Get-NamedProperty $Device.Source "firmware"
        return $(if ([string]::IsNullOrWhiteSpace([string]$value)) { $null } else { [string]$value })
    }
    $segments = @("system", "version.txt")
    $sourceState = Get-PathState $Device $segments "probe" 1
    if (-not $sourceState.Exists -or $null -eq $sourceState.Size) {
        return $null
    }
    $temporary = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        "kja-mtp-version-" + [Guid]::NewGuid().ToString("N")
    )
    $null = [System.IO.Directory]::CreateDirectory($temporary)
    $destination = [System.IO.Path]::Combine($temporary, "version.txt")
    try {
        Start-CopyFrom $Device $sourceState.Source $destination
        $wait = Wait-RemoteItem $Device $segments ([Int64]$sourceState.Size) "copy-from" $destination
        if ($wait.Status -ne "complete" -or -not [System.IO.File]::Exists($destination)) {
            return $null
        }
        $text = [System.IO.File]::ReadAllText($destination)
        $match = [regex]::Match($text, "(?:Kindle\s+)?([0-9]+(?:\.[0-9]+){1,4})")
        return $(if ($match.Success) { $match.Groups[1].Value } else { $null })
    }
    finally {
        if ([System.IO.Directory]::Exists($temporary)) {
            [System.IO.Directory]::Delete($temporary, $true)
        }
    }
}

function Get-TreeEntries($Device) {
    if ($Device.Backend -eq "fixture") {
        $entries = @()
        foreach ($folder in @(Get-NamedProperty $Device.Storage.Source "folders")) {
            $entries += [ordered]@{ path = [string]$folder; kind = "directory"; size = $null }
        }
        $files = Get-NamedProperty $Device.Storage.Source "files"
        if ($null -ne $files) {
            foreach ($property in $files.PSObject.Properties) {
                $entries += [ordered]@{ path = $property.Name; kind = "file"; size = [Int64]$property.Value }
            }
        }
        return @($entries | Sort-Object { $_.path })
    }
    $entries = @()
    $queue = [System.Collections.Queue]::new()
    $queue.Enqueue([PSCustomObject]@{ Prefix = ""; Item = $Device.Storage.Source })
    while ($queue.Count -gt 0) {
        $current = $queue.Dequeue()
        $folder = $current.Item.GetFolder
        if ($null -eq $folder) { throw "portable folder unavailable" }
        foreach ($item in @($folder.Items())) {
            $name = [string]$item.Name
            $null = Get-SafeSegments $name
            $relative = if ([string]::IsNullOrEmpty($current.Prefix)) { $name } else { $current.Prefix + "/" + $name }
            if ([bool]$item.IsFolder) {
                $entries += [ordered]@{ path = $relative; kind = "directory"; size = $null }
                $queue.Enqueue([PSCustomObject]@{ Prefix = $relative; Item = $item })
            }
            else {
                $size = Get-ExtendedProperty $item "System.Size"
                if ($null -eq $size) { throw "portable file size unavailable" }
                $entries += [ordered]@{ path = $relative; kind = "file"; size = [Int64]$size }
            }
        }
    }
    return @($entries | Sort-Object { $_.path })
}

function Invoke-MtpAction($Bundle) {
    if ($Action -notin @("list", "list-files", "copy-to", "copy-from", "exists", "free-bytes", "mkdir", "delete")) {
        return New-Failure "invalid_action" "不支持的 MTP 操作"
    }
    $devices = @(Select-KindleDevices $Bundle)
    if ($Action -eq "list") {
        if ($Arguments.Count -ne 0) {
            return New-Failure "invalid_arguments" "MTP 命令参数无效"
        }
        $publicDevices = @($devices | ForEach-Object {
            $free = Get-FreeBytes $_
            [ordered]@{
                id = $_.Id
                name = $_.Name
                storage = $_.StorageName
                device_code = $_.DeviceCode
                firmware = Get-DeviceFirmware $_
                free_bytes = $(if ($null -eq $free) { $null } else { [Int64]$free })
                read_only = $(if ($null -eq $free) { $null } else { $false })
            }
        })
        $payload = @{ ok = $true; action = $Action; devices = $publicDevices }
        if ($Bundle.Backend -eq "fixture") {
            $payload["fixture_diagnostics"] = @{
                expanded_tags = @($Bundle.Diagnostics.ExpandedTags)
                candidate_errors = [int]$Bundle.Diagnostics.CandidateErrors
            }
        }
        return New-Outcome $payload 0
    }

    $expectedArguments = if ($Action -in @("free-bytes", "list-files")) { 1 } elseif ($Action -in @("exists", "mkdir", "delete")) { 2 } else { 3 }
    if ($Arguments.Count -ne $expectedArguments) {
        return New-Failure "invalid_arguments" "MTP 命令参数无效"
    }
    $device = Resolve-Device $devices $Arguments[0]
    if ($null -eq $device) {
        return New-Failure "device_not_found" "未找到指定的 MTP 设备"
    }
    if ($Action -eq "free-bytes") {
        $free = Get-FreeBytes $device
        if ($null -eq $free) {
            return New-Failure "mtp_operation_failed" "无法读取 MTP 可用空间"
        }
        return New-Outcome @{ ok = $true; action = $Action; free_bytes = [Int64]$free } 0
    }
    if ($Action -eq "list-files") {
        try {
            $entries = @(Get-TreeEntries $device)
        }
        catch {
            return New-Failure "mtp_operation_failed" "无法取得安全的 MTP 文件清单"
        }
        return New-Outcome @{ ok = $true; action = $Action; entries = $entries } 0
    }

    $remoteArgument = if ($Action -eq "copy-to") { $Arguments[2] } else { $Arguments[1] }
    try {
        $segments = @(Get-SafeSegments $remoteArgument)
    }
    catch {
        return New-Failure "invalid_path" "MTP 路径无效"
    }
    if ($Action -eq "exists") {
        $state = Get-PathState $device $segments "probe" 1
        return New-Outcome @{ ok = $true; action = $Action; exists = [bool]$state.Exists } 0
    }
    if ($Action -eq "mkdir") {
        $existing = Get-PathState $device $segments "probe" 1
        if ($existing.Exists) {
            return New-Failure "mtp_operation_failed" "MTP 目录创建失败"
        }
        if ($device.Backend -eq "fixture") {
            return New-Outcome @{ ok = $true; action = $Action } 0
        }
        $parentSegments = @($segments[0..([Math]::Max(0, $segments.Count - 2))])
        if ($segments.Count -eq 1) { $parentSegments = @() }
        $parentItem = Resolve-ComMtpItem $device.Storage.Source $parentSegments
        if ($null -eq $parentItem -or $null -eq $parentItem.GetFolder) {
            return New-Failure "mtp_operation_failed" "MTP 目录创建失败"
        }
        $null = $parentItem.GetFolder.NewFolder($segments[-1])
        if ($null -eq (Resolve-ComMtpItem $device.Storage.Source $segments)) {
            return New-Failure "mtp_operation_failed" "MTP 目录创建失败"
        }
        return New-Outcome @{ ok = $true; action = $Action } 0
    }
    if ($Action -eq "delete") {
        if ($device.Backend -eq "fixture") {
            $fixtureState = Get-PathState $device $segments "probe" 1
            if (-not $fixtureState.Exists) { return New-Failure "mtp_operation_failed" "MTP 精确清理失败" }
            return New-Outcome @{ ok = $true; action = $Action } 0
        }
        $target = Resolve-ComMtpItem $device.Storage.Source $segments
        if ($null -eq $target) { return New-Failure "mtp_operation_failed" "MTP 精确清理失败" }
        if ([bool]$target.IsFolder -and @($target.GetFolder.Items()).Count -ne 0) {
            return New-Failure "mtp_operation_failed" "MTP 精确清理拒绝删除非空目录"
        }
        $null = $target.InvokeVerb("delete")
        for ($poll = 0; $poll -lt 100; $poll += 1) {
            if ($null -eq (Resolve-ComMtpItem $device.Storage.Source $segments)) {
                return New-Outcome @{ ok = $true; action = $Action } 0
            }
            Start-Sleep -Milliseconds 100
        }
        return New-Failure "mtp_operation_failed" "MTP 精确清理失败"
    }

    $localPath = [System.IO.Path]::GetFullPath(
        $(if ($Action -eq "copy-to") { $Arguments[1] } else { $Arguments[2] })
    )
    if ([System.IO.Path]::GetFileName($localPath) -cne $segments[-1]) {
        return New-Failure "invalid_path" "MTP 路径无效"
    }

    if ($Action -eq "copy-to") {
        if (-not [System.IO.File]::Exists($localPath)) {
            return New-Failure "mtp_operation_failed" "MTP 复制失败"
        }
        $existing = Get-PathState $device $segments "probe" 1
        if ($existing.Exists) {
            return New-Failure "mtp_operation_failed" "MTP 复制失败"
        }
        $expectedSize = ([System.IO.FileInfo]::new($localPath)).Length
        Start-CopyTo $device $segments $localPath
        $wait = Wait-RemoteItem $device $segments $expectedSize "copy-to"
    }
    else {
        $sourceState = Get-PathState $device $segments "probe" 1
        if (-not $sourceState.Exists -or $null -eq $sourceState.Size) {
            return New-Failure "mtp_operation_failed" "MTP 复制失败"
        }
        if ([System.IO.File]::Exists($localPath) -or
            -not [System.IO.Directory]::Exists([System.IO.Path]::GetDirectoryName($localPath))) {
            return New-Failure "mtp_operation_failed" "MTP 复制失败"
        }
        $expectedSize = [Int64]$sourceState.Size
        $sourceItem = if ($device.Backend -eq "fixture") {
            [PSCustomObject]@{ fixture_path = $segments -join "/" }
        } else { $sourceState.Source }
        Start-CopyFrom $device $sourceItem $localPath
        $wait = Wait-RemoteItem $device $segments $expectedSize "copy-from" $localPath
    }

    if ($wait.Status -eq "complete") {
        $payload = @{
            ok = $true
            action = $Action
            status = "complete"
            verified_after_polls = $wait.Polls
            timeout_ms = $wait.TimeoutMs
        }
        if ($device.Backend -eq "fixture") {
            $payload["test_mode"] = $true
        }
        return New-Outcome $payload 0
    }
    if ($wait.Status -eq "copy_in_progress") {
        return New-Failure "copy_in_progress" "MTP 复制仍在进行" @{
            status = "copy_in_progress"
            continue_waiting = $true
            retryable = $false
            timeout_ms = $wait.TimeoutMs
        }
    }
    return New-Failure "mtp_operation_failed" "MTP 复制失败" @{
        status = "failed"
        timeout_ms = $wait.TimeoutMs
    }
}

if ($Action -notin @("list", "list-files", "copy-to", "copy-from", "exists", "free-bytes", "mkdir", "delete")) {
    $outcome = New-Failure "invalid_action" "不支持的 MTP 操作"
    Write-Result $outcome.Payload
    exit $outcome.ExitCode
}

try {
    $bundle = if ([string]::IsNullOrWhiteSpace($FixturePath)) {
        Get-ComCandidateBundle
    }
    else {
        Get-FixtureCandidateBundle $FixturePath
    }
}
catch {
    $outcome = New-Failure "mtp_unavailable" "未检测到可用的 MTP 传输能力"
    Write-Result $outcome.Payload
    exit $outcome.ExitCode
}

try {
    $outcome = Invoke-MtpAction $bundle
}
catch {
    $outcome = New-Failure "mtp_operation_failed" "MTP 操作失败"
}

Write-Result $outcome.Payload
exit $outcome.ExitCode
