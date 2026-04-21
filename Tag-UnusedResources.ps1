<#
.SYNOPSIS
    Tags unused Azure resources as decommission candidates using a typed lifecycle taxonomy.

.DESCRIPTION
    This runbook queries Azure Resource Graph to identify:
    - Orphaned resources (unattached disks, NICs, PIPs, NSGs)           [Phase 1 scope]
    - Idle resources (deallocated VMs, empty App Service Plans)         [Phase 2 scope]
    - Stale resources (old snapshots, disk images)                      [Phase 2 scope]

    It applies a typed lifecycle tag family:
        lifecycle-state    = candidate
        lifecycle-reason   = <class-specific reason code>
        lifecycle-owner    = <derived from resource/RG/subscription tag, or "unresolved">
        lifecycle-reviewed = <ISO date of this scan>

    For backward compatibility during migration, TagMode=dual also writes the legacy
    tag family (decommission-candidate/detected/reason). TagMode=typed writes the new
    family only. TagMode=legacy writes the old family only.

    A secondary scan detects exempt resources whose lifecycle-reviewed date is older
    than ExemptReviewMaxAgeDays and demotes them back to candidate state. This closes
    the "tag-once-and-forget" loophole.

    IMPORTANT: This runbook does NOT delete resources. It only tags them. Disposition
    is handled by a downstream workflow that consumes the JSON export from this runbook.

.PARAMETER DryRun
    If $true, only reports what would be tagged without making changes.
    Default: $true (safe by default)

.PARAMETER Scope
    Which resource classes to scan.
      phase1 = orphan/unattached classes only (Disks, NICs, PIPs, NSGs) - ARG-sufficient, lowest blast radius
      phase2 = phase1 + idle/stale classes (VMs, ASPs, Snapshots, Images) - requires telemetry corroboration
      all    = same as phase2 (reserved for future extension)
    Default: phase1

.PARAMETER TagMode
    Tag family to write.
      legacy = decommission-candidate / decommission-detected / decommission-reason (v1.0 behaviour)
      typed  = lifecycle-state / lifecycle-reason / lifecycle-owner / lifecycle-reviewed
      dual   = both families (recommended during migration)
    Default: dual

.PARAMETER OwnerTagSource
    Name of the tag (on resource, then RG, then subscription) from which to derive the
    lifecycle-owner value. Default: "owner"

.PARAMETER ManagementGroupId
    Management Group ID to scan all subscriptions under it.
    If set, overrides the Subscriptions parameter.

.PARAMETER Subscriptions
    Array of subscription IDs to scan. If empty and ManagementGroupId not set,
    scans all accessible subscriptions.

.PARAMETER IdleWindowDays
    Number of days a VM must be deallocated to be considered idle. Default: 30
    Note: ARG does not expose the timestamp of the last deallocate event. When this
    parameter is > 0 and Scope includes VMs, the runbook enriches ARG results with
    Activity Log queries to establish the deallocation age. Set to 0 to skip the
    age check and tag all deallocated VMs regardless of duration.

.PARAMETER StaleWindowDays
    Number of days since creation for snapshots/images to be considered stale. Default: 90

.PARAMETER ExemptReviewMaxAgeDays
    Maximum age (in days) of lifecycle-reviewed on an exempt resource before it is
    demoted back to candidate state. Default: 180

.PARAMETER ExcludeResourceGroups
    Array of resource group names to exclude from tagging.

.PARAMETER ExcludeTagName
    Resources with this tag set to "true" will be excluded (legacy escape hatch).
    Default: "decommission-exclude"

.PARAMETER ExportPath
    Path to write the JSON summary export for consumption by the workflow layer.
    If empty, defaults to $env:TEMP\decommission-candidates-<timestamp>.json

.NOTES
    Version: 1.1.2
    Requires: Az.Accounts, Az.ResourceGraph, Az.Resources, Az.Monitor (for IdleWindowDays > 0)

    Changelog (v1.1.1 -> v1.1.2):
      - FIX: Correctly unwrap Search-AzGraph responses so only row records are processed (prevents array-shaped resource fields).
      - FIX: Harden owner resolution against null/array subscription IDs before cache lookups.
      - FIX: Make disk size conversion resilient to non-scalar values in cost estimation.
      - FIX: Repair review-expiry query by casting lifecycle-reviewed to datetime before comparison.

    Changelog (v1.1.0 -> v1.1.1):
      - FIX: Search-AzGraph calls now paginate via SkipToken (previously capped silently at 1000 rows).
              Affected both resource-class scans and subscription discovery. At MG scale this caused
              missed candidates AND silent owner-resolution failures for resources in overflow subs.

    Changelog (v1.0.0 -> v1.1.0):
      - Added typed lifecycle-* tag family with dual-write migration mode
      - Added lifecycle-owner derivation from resource/RG/subscription tags
      - Fixed dead $IdleWindowDays parameter (now enforced via Activity Log when > 0)
      - Added Scope parameter defaulting to phase1 (ARG-sufficient classes only)
      - Added review-expiry scan that demotes stale exemptions back to candidate
      - Added JSON export of scan results for downstream workflow consumption
      - Removed StaleImages from default scope (cannot verify age from ARG)
#>

param(
    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $true,

    [Parameter(Mandatory = $false)]
    [ValidateSet("phase1", "phase2", "all")]
    [string]$Scope = "phase1",

    [Parameter(Mandatory = $false)]
    [ValidateSet("legacy", "typed", "dual")]
    [string]$TagMode = "dual",

    [Parameter(Mandatory = $false)]
    [string]$OwnerTagSource = "owner",

    [Parameter(Mandatory = $false)]
    [string]$ManagementGroupId = "",

    [Parameter(Mandatory = $false)]
    [string[]]$Subscriptions = @(),

    [Parameter(Mandatory = $false)]
    [int]$IdleWindowDays = 30,

    [Parameter(Mandatory = $false)]
    [int]$StaleWindowDays = 90,

    [Parameter(Mandatory = $false)]
    [int]$ExemptReviewMaxAgeDays = 180,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeResourceGroups = @(),

    [Parameter(Mandatory = $false)]
    [string]$ExcludeTagName = "decommission-exclude",

    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ""
)

#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
}

function Invoke-ArgPaged {
    # Shared pagination helper. Search-AzGraph returns up to 1000 rows per call
    # and a SkipToken when more remain. We loop until SkipToken is empty.
    param(
        [string]$Query,
        [string]$ManagementGroupId,
        [string[]]$Subscriptions,
        [int]$PageSize = 1000,
        [int]$MaxPages = 100   # hard cap against runaway queries; 100k rows
    )

    $all = New-Object System.Collections.Generic.List[object]
    $skipToken = $null
    $page = 0

    do {
        $params = @{
            Query = $Query
            First = $PageSize
        }
        if ($ManagementGroupId -ne "") {
            $params.ManagementGroup = $ManagementGroupId
        } elseif ($Subscriptions -and $Subscriptions.Count -gt 0) {
            $params.Subscription = $Subscriptions
        }
        if ($skipToken) { $params.SkipToken = $skipToken }

        $response = Search-AzGraph @params
        if ($response) {
            $rows = @()
            if ($response.PSObject.Properties.Name -contains 'Data') {
                # Some Az.ResourceGraph versions return a wrapper object with Data + SkipToken
                $rows = @($response.Data)
                $skipToken = $response.SkipToken
            }
            else {
                # Other versions return row objects directly (array may carry SkipToken note property)
                $rows = @($response)
                $skipToken = $response.SkipToken
            }

            foreach ($row in $rows) {
                if ($null -ne $row) { $all.Add($row) | Out-Null }
            }
        } else {
            $skipToken = $null
        }

        $page++
        if ($page -ge $MaxPages) {
            Write-Log "Invoke-ArgPaged hit MaxPages ($MaxPages); results may be incomplete." -Level "WARN"
            break
        }
    } while ($skipToken)

    return ,$all.ToArray()
}

function Get-ResourceGraphResults {
    param(
        [string]$Query,
        [string]$ManagementGroupId,
        [string[]]$Subscriptions
    )

    if ($ManagementGroupId -ne "") {
        Write-Log "Querying Management Group: $ManagementGroupId" -Level "DEBUG"
    }
    return Invoke-ArgPaged -Query $Query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
}

function Get-FirstNonEmptyString {
    param([object]$Value)

    if ($null -eq $Value) { return $null }

    if ($Value -is [System.Array]) {
        foreach ($candidate in $Value) {
            $s = [string]$candidate
            if (-not [string]::IsNullOrWhiteSpace($s)) { return $s }
        }
        return $null
    }

    $single = [string]$Value
    if ([string]::IsNullOrWhiteSpace($single)) { return $null }
    return $single
}

function Convert-ToIntSafe {
    param(
        [object]$Value,
        [int]$Default = 0
    )

    $scalar = Get-FirstNonEmptyString -Value $Value
    if ($null -eq $scalar) { return $Default }

    $parsed = 0
    if ([int]::TryParse($scalar, [ref]$parsed)) { return $parsed }
    return $Default
}

# --- Owner derivation -------------------------------------------------------
# Cache per RG and per subscription to avoid re-querying for every resource.
$script:RgOwnerCache  = @{}
$script:SubOwnerCache = @{}

function Initialize-SubscriptionOwnerCache {
    param([object[]]$SubsInScope, [string]$OwnerTagSource)

    foreach ($sub in $SubsInScope) {
        $ownerValue = $null
        if ($sub.tags -and $sub.tags.PSObject.Properties.Name -contains $OwnerTagSource) {
            $ownerValue = $sub.tags.$OwnerTagSource
        }
        $script:SubOwnerCache[$sub.subscriptionId] = $ownerValue
    }
}

function Get-RgOwner {
    param([string]$SubscriptionId, [string]$ResourceGroup, [string]$OwnerTagSource)

    $cacheKey = "$SubscriptionId/$ResourceGroup"
    if ($script:RgOwnerCache.ContainsKey($cacheKey)) {
        return $script:RgOwnerCache[$cacheKey]
    }

    $ownerValue = $null
    try {
        $currentCtx = Get-AzContext
        if ($currentCtx.Subscription.Id -ne $SubscriptionId) {
            Set-AzContext -SubscriptionId $SubscriptionId -ErrorAction Stop | Out-Null
        }
        $rg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction Stop
        if ($rg.Tags -and $rg.Tags.ContainsKey($OwnerTagSource)) {
            $ownerValue = $rg.Tags[$OwnerTagSource]
        }
    }
    catch {
        Write-Log "Could not resolve RG owner for $cacheKey : $($_.Exception.Message)" -Level "DEBUG"
    }

    $script:RgOwnerCache[$cacheKey] = $ownerValue
    return $ownerValue
}

function Resolve-LifecycleOwner {
    param([object]$Resource, [string]$OwnerTagSource)

    # 1. Resource-level tag (ARG exposes tags object)
    if ($Resource.PSObject.Properties.Name -contains 'tags' -and $Resource.tags) {
        $tagObj = $Resource.tags
        if ($tagObj.PSObject.Properties.Name -contains $OwnerTagSource) {
            $v = $tagObj.$OwnerTagSource
            if ($v) { return $v }
        }
    }

    $subscriptionId = Get-FirstNonEmptyString -Value $Resource.subscriptionId
    $resourceGroup  = Get-FirstNonEmptyString -Value $Resource.resourceGroup

    # 2. Resource Group tag
    if ($subscriptionId -and $resourceGroup) {
        $rgOwner = Get-RgOwner -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -OwnerTagSource $OwnerTagSource
        if ($rgOwner) { return $rgOwner }
    }

    # 3. Subscription tag
    if ($subscriptionId -and $script:SubOwnerCache.ContainsKey($subscriptionId)) {
        $subOwner = $script:SubOwnerCache[$subscriptionId]
        if ($subOwner) { return $subOwner }
    }

    # 4. Fallback
    return "unresolved"
}

# --- Tag application --------------------------------------------------------

function Add-DecommissionTag {
    param(
        [string]$ResourceId,
        [string]$Reason,
        [string]$Owner,
        [bool]$DryRun,
        [string]$TagMode
    )

    $today = Get-Date -Format "yyyy-MM-dd"
    $tags = @{}

    if ($TagMode -in @("legacy", "dual")) {
        $tags["decommission-candidate"] = "true"
        $tags["decommission-detected"]  = $today
        $tags["decommission-reason"]    = $Reason
    }
    if ($TagMode -in @("typed", "dual")) {
        $tags["lifecycle-state"]    = "candidate"
        $tags["lifecycle-reason"]   = $Reason
        $tags["lifecycle-owner"]    = if ($Owner) { $Owner } else { "unresolved" }
        $tags["lifecycle-reviewed"] = $today
    }

    if ($DryRun) {
        Write-Log "[DRY RUN] Would tag: $ResourceId (Reason: $Reason, Owner: $Owner, Mode: $TagMode)" -Level "INFO"
        return $true
    }

    try {
        $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop
        $existingTags = $resource.Tags
        if ($null -eq $existingTags) { $existingTags = @{} }

        # Merge: do not overwrite existing tag keys (preserves manually set lifecycle-* values)
        foreach ($key in $tags.Keys) {
            if (-not $existingTags.ContainsKey($key)) {
                $existingTags[$key] = $tags[$key]
            }
        }

        Set-AzResource -ResourceId $ResourceId -Tag $existingTags -Force -ErrorAction Stop | Out-Null
        Write-Log "Tagged: $ResourceId (Reason: $Reason, Owner: $Owner)" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to tag $ResourceId : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Set-LifecycleStateCandidate {
    # Used by the review-expiry scan to flip an expired "exempt" back to "candidate"
    param(
        [string]$ResourceId,
        [string]$Reason,
        [bool]$DryRun
    )

    $today = Get-Date -Format "yyyy-MM-dd"
    if ($DryRun) {
        Write-Log "[DRY RUN] Would demote exempt->candidate: $ResourceId (Reason: $Reason)" -Level "INFO"
        return $true
    }

    try {
        $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop
        $existingTags = $resource.Tags
        if ($null -eq $existingTags) { $existingTags = @{} }

        $existingTags["lifecycle-state"]    = "candidate"
        $existingTags["lifecycle-reason"]   = $Reason
        $existingTags["lifecycle-reviewed"] = $today

        Set-AzResource -ResourceId $ResourceId -Tag $existingTags -Force -ErrorAction Stop | Out-Null
        Write-Log "Demoted exempt->candidate: $ResourceId (Reason: $Reason)" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to demote $ResourceId : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# --- VM deallocation age via Activity Log -----------------------------------

function Test-VmDeallocatedLongerThan {
    param(
        [object]$Vm,
        [int]$IdleWindowDays
    )

    if ($IdleWindowDays -le 0) { return $true }  # age check disabled

    try {
        $currentCtx = Get-AzContext
        if ($currentCtx.Subscription.Id -ne $Vm.subscriptionId) {
            Set-AzContext -SubscriptionId $Vm.subscriptionId -ErrorAction Stop | Out-Null
        }

        # Activity Log retention is 90 days. If we don't find a deallocate event in that window,
        # the VM has been deallocated for at least 90 days -> treat as idle.
        $windowStart = (Get-Date).AddDays(-90)
        $events = Get-AzActivityLog -ResourceId $Vm.id -StartTime $windowStart -WarningAction SilentlyContinue -ErrorAction Stop |
            Where-Object { $_.OperationName.Value -eq 'Microsoft.Compute/virtualMachines/deallocate/action' -and $_.Status.Value -eq 'Succeeded' } |
            Sort-Object EventTimestamp -Descending

        if (-not $events -or $events.Count -eq 0) {
            # No deallocate event in last 90 days -> has been deallocated for >=90 days
            return $IdleWindowDays -le 90
        }

        $lastDeallocate = $events[0].EventTimestamp
        $ageDays = ((Get-Date) - $lastDeallocate).TotalDays
        return $ageDays -ge $IdleWindowDays
    }
    catch {
        Write-Log "Could not determine deallocation age for $($Vm.id): $($_.Exception.Message). Excluding from tagging." -Level "WARN"
        return $false  # fail-safe: if we can't determine age, do not tag
    }
}

#endregion

#region Main Execution

$scriptStartTime = Get-Date

Write-Log "============================================================"
Write-Log "     UNUSED RESOURCE TAGGING AUTOMATION (v1.1.0)"
Write-Log "============================================================"
Write-Log ""
Write-Log "CONFIGURATION:"
Write-Log "  DryRun Mode:              $DryRun $(if ($DryRun) { '(no changes will be made)' } else { '*** LIVE MODE - TAGS WILL BE APPLIED ***' })"
Write-Log "  Scope:                    $Scope"
Write-Log "  TagMode:                  $TagMode"
Write-Log "  OwnerTagSource:           $OwnerTagSource"
Write-Log "  Idle Window:              $IdleWindowDays days $(if ($IdleWindowDays -eq 0) { '(age check disabled)' })"
Write-Log "  Stale Window:             $StaleWindowDays days"
Write-Log "  Exempt Review Max Age:    $ExemptReviewMaxAgeDays days"
Write-Log "  Exclude Tag:              $ExcludeTagName"
Write-Log "  Exclude RGs:              $(if ($ExcludeResourceGroups.Count -gt 0) { $ExcludeResourceGroups -join ', ' } else { '(none)' })"
Write-Log ""
Write-Log "SCOPE:"
if ($ManagementGroupId) {
    Write-Log "  Management Group:         $ManagementGroupId"
    Write-Log "  (All subscriptions under this MG hierarchy will be scanned)"
} elseif ($Subscriptions.Count -gt 0) {
    Write-Log "  Subscriptions:            $($Subscriptions.Count) specified"
    foreach ($sub in $Subscriptions) {
        Write-Log "    - $sub"
    }
} else {
    Write-Log "  Subscriptions:            All accessible to current identity"
}
Write-Log ""

# Discover subscriptions in scope
Write-Log "DISCOVERING SUBSCRIPTIONS IN SCOPE..."
$subscriptionQuery = "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId, name, tags"
try {
    $subsInScope = Invoke-ArgPaged -Query $subscriptionQuery -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    Write-Log "  Found $($subsInScope.Count) subscriptions in scope:"
    foreach ($sub in $subsInScope) {
        Write-Log "    - $($sub.name) ($($sub.subscriptionId))"
    }
}
catch {
    Write-Log "  Warning: Could not enumerate subscriptions: $($_.Exception.Message)" -Level "WARN"
    $subsInScope = @()
}
Write-Log ""

# Initialize subscription-level owner cache
Initialize-SubscriptionOwnerCache -SubsInScope $subsInScope -OwnerTagSource $OwnerTagSource

# Build exclusion filter
Write-Log "FILTERS:"
$excludeRgFilter = ""
if ($ExcludeResourceGroups.Count -gt 0) {
    $rgList = ($ExcludeResourceGroups | ForEach-Object { "'$_'" }) -join ", "
    $excludeRgFilter = "| where resourceGroup !in~ ($rgList)"
    Write-Log "  Excluded Resource Groups: $($ExcludeResourceGroups -join ', ')"
} else {
    Write-Log "  Excluded Resource Groups: (none)"
}
Write-Log "  Excluded by Tag:          Resources with '$ExcludeTagName = true'"
Write-Log "  Excluded by State:        Resources with 'lifecycle-state = exempt' (unless review expired)"
Write-Log "  Skipped:                  Resources already tagged candidate (legacy or typed)"
Write-Log ""

$excludeTagFilter      = "| where isnull(tags['$ExcludeTagName']) or tags['$ExcludeTagName'] != 'true'"
$excludeExemptFilter   = "| where isnull(tags['lifecycle-state']) or tags['lifecycle-state'] != 'exempt'"
$alreadyTaggedFilter   = "| where (isnull(tags['decommission-candidate']) or tags['decommission-candidate'] != 'true') and (isnull(tags['lifecycle-state']) or tags['lifecycle-state'] != 'candidate')"

# Determine class list from Scope
$phase1Classes = @("UnattachedDisks", "OrphanNICs", "OrphanPIPs", "OrphanNSGs")
$phase2Classes = $phase1Classes + @("DeallocatedVMs", "EmptyASPs", "StaleSnapshots")
# StaleImages deliberately excluded from default scope: ARG cannot verify age.
$activeClasses = switch ($Scope) {
    "phase1" { $phase1Classes }
    "phase2" { $phase2Classes }
    "all"    { $phase2Classes }
}
Write-Log "ACTIVE CLASSES: $($activeClasses -join ', ')"
Write-Log ""

# Track results with details
$summary = @{}
foreach ($c in @("UnattachedDisks","OrphanNICs","OrphanPIPs","OrphanNSGs","DeallocatedVMs","EmptyASPs","StaleSnapshots","StaleImages","ReviewExpired")) {
    $summary[$c] = @{ Found = 0; Tagged = 0; Skipped = 0; Details = @() }
}

$costEstimates = @{
    "UnattachedDisks" = 0.0
    "OrphanPIPs"      = 0.0
    "DeallocatedVMs"  = 0.0
    "EmptyASPs"       = 0.0
    "StaleSnapshots"  = 0.0
}

# Helper to get subscription name
function Get-SubscriptionName {
    param([string]$SubscriptionId)
    $sub = $subsInScope | Where-Object { $_.subscriptionId -eq $SubscriptionId }
    if ($sub) { return $sub.name }
    return $SubscriptionId
}

# Helper to estimate monthly cost (EUR, West Europe list prices; drift expected)
function Get-EstimatedMonthlyCost {
    param([string]$ResourceType, [object]$Resource)

    switch ($ResourceType) {
        "Disk" {
            $sizeGB = Convert-ToIntSafe -Value $Resource.diskSizeGB -Default 0
            $sku = $Resource.sku_name

            if ($sku -match "Premium") {
                if ($sizeGB -le 32)    { return 5.28 }
                elseif ($sizeGB -le 64)    { return 10.21 }
                elseif ($sizeGB -le 128)   { return 19.71 }
                elseif ($sizeGB -le 256)   { return 38.02 }
                elseif ($sizeGB -le 512)   { return 73.22 }
                elseif ($sizeGB -le 1024)  { return 140.74 }
                elseif ($sizeGB -le 2048)  { return 270.34 }
                else                       { return 519.48 }
            }
            elseif ($sku -match "StandardSSD") {
                if ($sizeGB -le 32)    { return 2.40 }
                elseif ($sizeGB -le 64)    { return 4.80 }
                elseif ($sizeGB -le 128)   { return 9.60 }
                elseif ($sizeGB -le 256)   { return 18.43 }
                elseif ($sizeGB -le 512)   { return 35.33 }
                elseif ($sizeGB -le 1024)  { return 67.58 }
                else                       { return 129.54 }
            }
            else {
                return $sizeGB * 0.04
            }
        }
        "PublicIP" {
            $sku = $Resource.sku_name
            if ($sku -eq "Standard") { return 3.65 }
            else                     { return 2.63 }
        }
        "VM" {
            $vmSize = $Resource.vmSize
            if     ($vmSize -match "Standard_B1") { return 8.0 }
            elseif ($vmSize -match "Standard_B2") { return 30.0 }
            elseif ($vmSize -match "Standard_D2") { return 70.0 }
            elseif ($vmSize -match "Standard_D4") { return 140.0 }
            elseif ($vmSize -match "Standard_D8") { return 280.0 }
            elseif ($vmSize -match "Standard_E2") { return 100.0 }
            elseif ($vmSize -match "Standard_E4") { return 200.0 }
            else                                  { return 50.0 }
        }
        "AppServicePlan" {
            $sku = $Resource.sku_name
            switch ($sku) {
                "F1"    { return 0.0 }
                "B1"    { return 12.41 }
                "B2"    { return 24.82 }
                "B3"    { return 49.64 }
                "S1"    { return 66.43 }
                "S2"    { return 132.86 }
                "S3"    { return 265.72 }
                "P1v2"  { return 73.73 }
                "P2v2"  { return 147.46 }
                "P3v2"  { return 294.92 }
                "P1v3"  { return 89.79 }
                "P2v3"  { return 179.58 }
                "P3v3"  { return 359.16 }
                default { return 30.0 }
            }
        }
        "Snapshot" {
            $sizeGB = Convert-ToIntSafe -Value $Resource.diskSizeGB -Default 0
            return $sizeGB * 0.05
        }
        default { return 0.0 }
    }
}

function Write-ResourceTable {
    param([string]$Category, [object[]]$Resources, [hashtable]$ExtraFields)

    $Resources = @($Resources | Where-Object { $null -ne $_ })
    if ($Resources.Count -eq 1 -and $Resources[0] -is [System.Array]) {
        $Resources = @($Resources[0] | Where-Object { $null -ne $_ })
    }

    if ($Resources.Count -eq 0) {
        Write-Log "    (no resources found)"
        return
    }

    Write-Log "    +-----------------------------------------------------------------------------"
    $counter = 1
    foreach ($res in $Resources) {
        $resourceName = Get-FirstNonEmptyString -Value $res.name
        $subscriptionId = Get-FirstNonEmptyString -Value $res.subscriptionId
        $resourceGroup = Get-FirstNonEmptyString -Value $res.resourceGroup
        $location = Get-FirstNonEmptyString -Value $res.location
        $resourceId = Get-FirstNonEmptyString -Value $res.id

        $subName = Get-SubscriptionName -SubscriptionId $subscriptionId
        Write-Log "    | [$counter] $resourceName"
        Write-Log "    |     Subscription:   $subName"
        Write-Log "    |     Resource Group: $resourceGroup"
        Write-Log "    |     Location:       $location"
        Write-Log "    |     Resource ID:    $resourceId"

        if ($ExtraFields) {
            foreach ($label in $ExtraFields.Keys) {
                $fieldPath = $ExtraFields[$label]
                $value = $res
                foreach ($part in $fieldPath.Split('.')) {
                    if ($value) { $value = $value.$part }
                }
                if ($value) {
                    Write-Log "    |     ${label}: $value"
                }
            }
        }

        if ($counter -lt $Resources.Count) { Write-Log "    |" }
        $counter++
    }
    Write-Log "    +-----------------------------------------------------------------------------"
}

Write-Log "============================================================"
Write-Log "                   SCANNING RESOURCES"
Write-Log "============================================================"
Write-Log ""

# Capture all candidate records for JSON export
$exportRecords = New-Object System.Collections.Generic.List[object]

function Add-ExportRecord {
    param([string]$Category, [object]$Resource, [string]$Reason, [string]$Owner, [double]$EstCostMonth)
    $exportRecords.Add([pscustomobject]@{
        category       = $Category
        reason         = $Reason
        owner          = $Owner
        estCostEurMo   = [math]::Round($EstCostMonth, 2)
        resourceId     = $Resource.id
        name           = $Resource.name
        resourceGroup  = $Resource.resourceGroup
        subscriptionId = $Resource.subscriptionId
        location       = $Resource.location
        detectedAt     = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    }) | Out-Null
}

#region Phase 1 classes (orphan / unattached)

if ("UnattachedDisks" -in $activeClasses) {
    Write-Log "[UNATTACHED MANAGED DISKS]"
    Write-Log "    Criteria: Disk not attached to any VM (diskState = 'Unattached')"
    $scanStart = Get-Date
    $query = @"
resources
| where type =~ 'microsoft.compute/disks'
| where managedBy == '' or isnull(managedBy)
| where properties.diskState == 'Unattached'
$excludeRgFilter
$excludeTagFilter
$excludeExemptFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, tags, sku_name=sku.name, diskSizeGB=properties.diskSizeGB
"@
    $disks = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["UnattachedDisks"].Found = $disks.Count
    Write-Log "    Found: $($disks.Count) unattached disks (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "UnattachedDisks" -Resources $disks -ExtraFields @{ "SKU" = "sku_name"; "Size (GB)" = "diskSizeGB" }

    foreach ($disk in $disks) {
        $owner = Resolve-LifecycleOwner -Resource $disk -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "Disk" -Resource $disk
        $ok    = Add-DecommissionTag -ResourceId $disk.id -Reason "Orphan-UnattachedDisk" -Owner $owner -DryRun $DryRun -TagMode $TagMode
        if ($ok) { $summary["UnattachedDisks"].Tagged++ }
        $costEstimates["UnattachedDisks"] += $cost
        Add-ExportRecord -Category "UnattachedDisks" -Resource $disk -Reason "Orphan-UnattachedDisk" -Owner $owner -EstCostMonth $cost
    }
    Write-Log ""
}

if ("OrphanNICs" -in $activeClasses) {
    Write-Log "[ORPHAN NETWORK INTERFACES]"
    Write-Log "    Criteria: NIC not attached to any VM or Private Endpoint"
    $scanStart = Get-Date
    $query = @"
resources
| where type =~ 'microsoft.network/networkinterfaces'
| where isnull(properties.virtualMachine.id) or properties.virtualMachine.id == ''
| where isnull(properties.privateEndpoint.id) or properties.privateEndpoint.id == ''
$excludeRgFilter
$excludeTagFilter
$excludeExemptFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
    $nics = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["OrphanNICs"].Found = $nics.Count
    Write-Log "    Found: $($nics.Count) orphan NICs (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "OrphanNICs" -Resources $nics -ExtraFields @{}

    foreach ($nic in $nics) {
        $owner = Resolve-LifecycleOwner -Resource $nic -OwnerTagSource $OwnerTagSource
        $ok    = Add-DecommissionTag -ResourceId $nic.id -Reason "Orphan-NoVMAttached" -Owner $owner -DryRun $DryRun -TagMode $TagMode
        if ($ok) { $summary["OrphanNICs"].Tagged++ }
        Add-ExportRecord -Category "OrphanNICs" -Resource $nic -Reason "Orphan-NoVMAttached" -Owner $owner -EstCostMonth 0.0
    }
    Write-Log ""
}

if ("OrphanPIPs" -in $activeClasses) {
    Write-Log "[ORPHAN PUBLIC IP ADDRESSES]"
    Write-Log "    Criteria: Public IP not associated with any resource"
    $scanStart = Get-Date
    $query = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnull(properties.ipConfiguration.id) or properties.ipConfiguration.id == ''
| where isnull(properties.natGateway.id) or properties.natGateway.id == ''
$excludeRgFilter
$excludeTagFilter
$excludeExemptFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, tags, sku_name=sku.name
"@
    $pips = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["OrphanPIPs"].Found = $pips.Count
    Write-Log "    Found: $($pips.Count) orphan Public IPs (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "OrphanPIPs" -Resources $pips -ExtraFields @{ "SKU" = "sku_name" }

    foreach ($pip in $pips) {
        $owner = Resolve-LifecycleOwner -Resource $pip -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "PublicIP" -Resource $pip
        $ok    = Add-DecommissionTag -ResourceId $pip.id -Reason "Orphan-NotAssociated" -Owner $owner -DryRun $DryRun -TagMode $TagMode
        if ($ok) { $summary["OrphanPIPs"].Tagged++ }
        $costEstimates["OrphanPIPs"] += $cost
        Add-ExportRecord -Category "OrphanPIPs" -Resource $pip -Reason "Orphan-NotAssociated" -Owner $owner -EstCostMonth $cost
    }
    Write-Log ""
}

if ("OrphanNSGs" -in $activeClasses) {
    Write-Log "[ORPHAN NETWORK SECURITY GROUPS]"
    Write-Log "    Criteria: NSG not attached to any subnet or NIC"
    $scanStart = Get-Date
    $query = @"
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| where isnull(properties.subnets) or array_length(properties.subnets) == 0
| where isnull(properties.networkInterfaces) or array_length(properties.networkInterfaces) == 0
$excludeRgFilter
$excludeTagFilter
$excludeExemptFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
    $nsgs = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["OrphanNSGs"].Found = $nsgs.Count
    Write-Log "    Found: $($nsgs.Count) orphan NSGs (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "OrphanNSGs" -Resources $nsgs -ExtraFields @{}

    foreach ($nsg in $nsgs) {
        $owner = Resolve-LifecycleOwner -Resource $nsg -OwnerTagSource $OwnerTagSource
        $ok    = Add-DecommissionTag -ResourceId $nsg.id -Reason "Orphan-NotAttached" -Owner $owner -DryRun $DryRun -TagMode $TagMode
        if ($ok) { $summary["OrphanNSGs"].Tagged++ }
        Add-ExportRecord -Category "OrphanNSGs" -Resource $nsg -Reason "Orphan-NotAttached" -Owner $owner -EstCostMonth 0.0
    }
    Write-Log ""
}

#endregion

#region Phase 2 classes (idle / stale)

if ("DeallocatedVMs" -in $activeClasses) {
    Write-Log "[DEALLOCATED VIRTUAL MACHINES]"
    if ($IdleWindowDays -gt 0) {
        Write-Log "    Criteria: VM in 'Deallocated' power state for >= $IdleWindowDays days (Activity Log corroborated)"
    } else {
        Write-Log "    Criteria: VM in 'Deallocated' power state (age check disabled)"
    }
    $scanStart = Get-Date
    $query = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where properties.extended.instanceView.powerState.code =~ 'PowerState/deallocated'
$excludeRgFilter
$excludeTagFilter
$excludeExemptFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, tags, vmSize=properties.hardwareProfile.vmSize
"@
    $vmsAll = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions

    # Enforce idle-window via Activity Log
    $vms = @()
    $skippedForAge = 0
    foreach ($vm in $vmsAll) {
        if (Test-VmDeallocatedLongerThan -Vm $vm -IdleWindowDays $IdleWindowDays) {
            $vms += $vm
        } else {
            $skippedForAge++
        }
    }

    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["DeallocatedVMs"].Found   = $vms.Count
    $summary["DeallocatedVMs"].Skipped = $skippedForAge
    Write-Log "    Found: $($vms.Count) deallocated VMs past idle window (scan took $([math]::Round($scanDuration, 2))s; $skippedForAge skipped as too recent)"
    Write-ResourceTable -Category "DeallocatedVMs" -Resources $vms -ExtraFields @{ "VM Size" = "vmSize" }

    foreach ($vm in $vms) {
        $owner = Resolve-LifecycleOwner -Resource $vm -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "VM" -Resource $vm
        $ok    = Add-DecommissionTag -ResourceId $vm.id -Reason "Idle-DeallocatedGt${IdleWindowDays}d" -Owner $owner -DryRun $DryRun -TagMode $TagMode
        if ($ok) { $summary["DeallocatedVMs"].Tagged++ }
        $costEstimates["DeallocatedVMs"] += $cost
        Add-ExportRecord -Category "DeallocatedVMs" -Resource $vm -Reason "Idle-DeallocatedGt${IdleWindowDays}d" -Owner $owner -EstCostMonth $cost
    }
    Write-Log ""
}

if ("EmptyASPs" -in $activeClasses) {
    Write-Log "[EMPTY APP SERVICE PLANS]"
    Write-Log "    Criteria: App Service Plan with 0 hosted apps"
    $scanStart = Get-Date
    $query = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0
$excludeRgFilter
$excludeTagFilter
$excludeExemptFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, tags, sku_name=sku.name
"@
    $asps = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["EmptyASPs"].Found = $asps.Count
    Write-Log "    Found: $($asps.Count) empty App Service Plans (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "EmptyASPs" -Resources $asps -ExtraFields @{ "SKU" = "sku_name" }

    foreach ($asp in $asps) {
        $owner = Resolve-LifecycleOwner -Resource $asp -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "AppServicePlan" -Resource $asp
        $ok    = Add-DecommissionTag -ResourceId $asp.id -Reason "Idle-NoAppsHosted" -Owner $owner -DryRun $DryRun -TagMode $TagMode
        if ($ok) { $summary["EmptyASPs"].Tagged++ }
        $costEstimates["EmptyASPs"] += $cost
        Add-ExportRecord -Category "EmptyASPs" -Resource $asp -Reason "Idle-NoAppsHosted" -Owner $owner -EstCostMonth $cost
    }
    Write-Log ""
}

if ("StaleSnapshots" -in $activeClasses) {
    Write-Log "[STALE SNAPSHOTS]"
    Write-Log "    Criteria: Snapshot created more than $StaleWindowDays days ago"
    $scanStart = Get-Date
    $staleDate = (Get-Date).AddDays(-$StaleWindowDays).ToString("yyyy-MM-ddTHH:mm:ssZ")

    $query = @"
resources
| where type =~ 'microsoft.compute/snapshots'
| where properties.timeCreated < datetime('$staleDate')
$excludeRgFilter
$excludeTagFilter
$excludeExemptFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, tags, diskSizeGB=properties.diskSizeGB, timeCreated=properties.timeCreated
"@
    $snapshots = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["StaleSnapshots"].Found = $snapshots.Count
    Write-Log "    Found: $($snapshots.Count) stale snapshots (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "StaleSnapshots" -Resources $snapshots -ExtraFields @{ "Size (GB)" = "diskSizeGB"; "Created" = "timeCreated" }

    foreach ($snapshot in $snapshots) {
        $owner = Resolve-LifecycleOwner -Resource $snapshot -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "Snapshot" -Resource $snapshot
        $ok    = Add-DecommissionTag -ResourceId $snapshot.id -Reason "Stale-OlderThan${StaleWindowDays}Days" -Owner $owner -DryRun $DryRun -TagMode $TagMode
        if ($ok) { $summary["StaleSnapshots"].Tagged++ }
        $costEstimates["StaleSnapshots"] += $cost
        Add-ExportRecord -Category "StaleSnapshots" -Resource $snapshot -Reason "Stale-OlderThan${StaleWindowDays}Days" -Owner $owner -EstCostMonth $cost
    }
    Write-Log ""
}

# StaleImages intentionally excluded: ARG does not expose creation date.
# Re-introduce once the Activity-Log-based age enrichment is implemented for this class.

#endregion

#region Review-expiry scan (typed/dual tag mode only)

if ($TagMode -in @("typed", "dual")) {
    Write-Log "[REVIEW-EXPIRY SCAN]"
    Write-Log "    Criteria: lifecycle-state = 'exempt' AND lifecycle-reviewed older than $ExemptReviewMaxAgeDays days"
    $scanStart = Get-Date
    $expiryDate = (Get-Date).AddDays(-$ExemptReviewMaxAgeDays).ToString("yyyy-MM-dd")

    $query = @"
resources
| where tags['lifecycle-state'] == 'exempt'
| extend lifecycleReviewed = todatetime(tostring(tags['lifecycle-reviewed']))
| where isnull(lifecycleReviewed) or lifecycleReviewed < datetime('$expiryDate')
$excludeRgFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
    $expired = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["ReviewExpired"].Found = $expired.Count
    Write-Log "    Found: $($expired.Count) exempt resources past review window (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "ReviewExpired" -Resources $expired -ExtraFields @{}

    foreach ($r in $expired) {
        $ok = Set-LifecycleStateCandidate -ResourceId $r.id -Reason "Review-Expired" -DryRun $DryRun
        if ($ok) { $summary["ReviewExpired"].Tagged++ }
        Add-ExportRecord -Category "ReviewExpired" -Resource $r -Reason "Review-Expired" -Owner "review-required" -EstCostMonth 0.0
    }
    Write-Log ""
}

#endregion

#region Summary Report & Export

$scriptEndTime = Get-Date
$totalDuration = ($scriptEndTime - $scriptStartTime).TotalSeconds

Write-Log "============================================================"
Write-Log "                      SUMMARY REPORT"
Write-Log "============================================================"
Write-Log ""
Write-Log "SCAN RESULTS:"
Write-Log "    +----------------------------+---------+---------+----------------+"
Write-Log "    | Category                   |  Found  |  Tagged | Est. Cost/mo   |"
Write-Log "    +----------------------------+---------+---------+----------------+"

$totalFound = 0
$totalTagged = 0
$totalCost = 0.0

$categoryOrder = @("UnattachedDisks","OrphanNICs","OrphanPIPs","OrphanNSGs","DeallocatedVMs","EmptyASPs","StaleSnapshots","ReviewExpired")
foreach ($category in $categoryOrder) {
    $found = $summary[$category].Found
    $tagged = $summary[$category].Tagged
    $cost = if ($costEstimates.ContainsKey($category)) { $costEstimates[$category] } else { 0.0 }
    $totalFound += $found
    $totalTagged += $tagged
    $totalCost += $cost
    $categoryName = $category.PadRight(26)
    $foundStr = $found.ToString().PadLeft(5)
    $taggedStr = $tagged.ToString().PadLeft(5)
    $costStr = ("EUR " + [math]::Round($cost, 2).ToString("N2")).PadLeft(12)
    Write-Log "    | $categoryName | $foundStr   | $taggedStr   | $costStr   |"
}

Write-Log "    +----------------------------+---------+---------+----------------+"
$totalFoundStr = $totalFound.ToString().PadLeft(5)
$totalTaggedStr = $totalTagged.ToString().PadLeft(5)
$totalCostStr = ("EUR " + [math]::Round($totalCost, 2).ToString("N2")).PadLeft(12)
Write-Log "    | TOTAL                      | $totalFoundStr   | $totalTaggedStr   | $totalCostStr   |"
Write-Log "    +----------------------------+---------+---------+----------------+"
Write-Log ""

# Owner resolution breakdown
$unresolvedCount = ($exportRecords | Where-Object { $_.owner -eq "unresolved" }).Count
$resolvedCount   = $exportRecords.Count - $unresolvedCount
$resolutionPct   = if ($exportRecords.Count -gt 0) { [math]::Round(100.0 * $resolvedCount / $exportRecords.Count, 1) } else { 0.0 }
Write-Log "OWNER RESOLUTION:"
Write-Log "    Resolved:                 $resolvedCount"
Write-Log "    Unresolved:               $unresolvedCount"
Write-Log "    Resolution rate:          $resolutionPct%"
Write-Log ""

Write-Log "POTENTIAL SAVINGS (indicative, West Europe list prices; reconcile against Cost Management):"
Write-Log "    Estimated Monthly:        EUR $([math]::Round($totalCost, 2).ToString("N2"))"
Write-Log "    Estimated Annual:         EUR $([math]::Round($totalCost * 12, 2).ToString("N2"))"
Write-Log ""

Write-Log "EXECUTION DETAILS:"
Write-Log "    Start Time:               $($scriptStartTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Log "    End Time:                 $($scriptEndTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Log "    Duration:                 $([math]::Round($totalDuration, 2)) seconds"
Write-Log "    Subscriptions:            $($subsInScope.Count) scanned"
Write-Log "    Scope:                    $Scope"
Write-Log "    TagMode:                  $TagMode"
Write-Log ""

# JSON export
if (-not $ExportPath) {
    $ExportPath = Join-Path $env:TEMP "decommission-candidates-$($scriptStartTime.ToString('yyyyMMddHHmmss')).json"
}
$exportEnvelope = [pscustomobject]@{
    schemaVersion       = "1.1"
    runStartedAt        = $scriptStartTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    runEndedAt          = $scriptEndTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    dryRun              = $DryRun
    scope               = $Scope
    tagMode             = $TagMode
    idleWindowDays      = $IdleWindowDays
    staleWindowDays     = $StaleWindowDays
    exemptReviewMaxAge  = $ExemptReviewMaxAgeDays
    subscriptionsScanned = $subsInScope.Count
    totals              = [pscustomobject]@{
        found           = $totalFound
        tagged          = $totalTagged
        estCostEurMonth = [math]::Round($totalCost, 2)
        ownerResolvedPct = $resolutionPct
    }
    perCategory         = ($summary.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{
            category = $_.Key
            found    = $_.Value.Found
            tagged   = $_.Value.Tagged
            skipped  = $_.Value.Skipped
        }
    })
    records             = $exportRecords
}

try {
    $exportEnvelope | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
    Write-Log "EXPORT:"
    Write-Log "    Wrote $($exportRecords.Count) records to: $ExportPath"
    Write-Log "    Consumed by: decommission workflow (notification, disposition, verification)"
    Write-Log ""
}
catch {
    Write-Log "Failed to write export: $($_.Exception.Message)" -Level "ERROR"
}

if ($DryRun) {
    Write-Log "============================================================"
    Write-Log "    DRY RUN COMPLETE - NO CHANGES WERE MADE"
    Write-Log "    Potential Monthly Savings: EUR $([math]::Round($totalCost, 2).ToString("N2"))"
    Write-Log "    Run with -DryRun `$false to apply tags"
    Write-Log "============================================================"
} else {
    Write-Log "============================================================"
    Write-Log "    TAGGING COMPLETE - $totalTagged resources tagged"
    Write-Log "    Potential Monthly Savings: EUR $([math]::Round($totalCost, 2).ToString("N2"))"
    Write-Log "============================================================"
}

#endregion

#endregion
