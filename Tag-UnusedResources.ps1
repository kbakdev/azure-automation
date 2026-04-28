<#
.SYNOPSIS
    Tags unused Azure resources as decommission candidates using the consolidated
    decommission-* tag family (v1.3.0 taxonomy).

.DESCRIPTION
    Scans Azure Resource Graph for:
      - Orphaned resources (unattached disks, NICs, PIPs, NSGs)    [Phase 1]
      - Idle resources (deallocated VMs, empty App Service Plans)  [Phase 2]
      - Stale resources (old snapshots)                             [Phase 2]

    TAG MODEL (v1.3.0) — nine tags, each with a single writer and a single semantic
    ==========================================================================

    SCRIPT WRITES (on first detection; owner/reason refreshed on subsequent scans):
        decommission-reviewed      = "false"
        decommission-disposition   = "delete"
        decommission-owner         = "<resolved email or 'unresolved'>"
        decommission-reason        = "orphaned" | "idle" | "stale"
        decommission-date-detected = YYYY-MM-DD

    OWNER WRITES (per-cycle decision OR standing policy):
        decommission-reviewed        = "true"
        decommission-date-reviewed   = YYYY-MM-DD
        decommission-disposition     = "delete" | "extend" | "exempted"  (overwrites script default)
        decommission-date-extended   = YYYY-MM-DD       (required when disposition = "extend")
        decommission-exempted-reason = "dr" | "compliance" | "planned-use" | "external-dep" | "legacy"
                                                          (required when disposition = "exempted")
        decommission-date-declared   = YYYY-MM-DD       (set by owner when disposition = "exempted")

    WORKFLOW STATE IS DERIVED, NOT STORED
    =====================================
    There is no decommission-state tag. The position in the workflow is computed from
    the combination of other tags:
        awaiting-delete (unreviewed) = disposition = "delete", reviewed = "false" (script default)
        awaiting-delete (confirmed)  = disposition = "delete", reviewed = "true", date-reviewed + 90d > today
        extend-active                = disposition = "extend", date-extended in future
        exempted                     = disposition = "exempted", date-declared within 180d

    EXPIRY POLICIES
    ===============
    Three disposition values, three expiry rules, enforced by the script:
        delete   -> 90 days from date-reviewed (only after owner confirms; unreviewed defaults never expire)
        extend   -> at date-extended (capped at +90d from date-reviewed at write time)
        exempted -> 180 days from date-declared

    On expiry, all three behave identically: companion tags are cleared,
    decommission-reviewed is reset to "false", disposition is restored to "delete",
    date-detected is refreshed, and the resource re-enters awaiting-delete (unreviewed).

    EXCLUSION SEMANTICS (re-scan)
    =============================
    A resource is skipped by re-scan if ANY of:
        - decommission-exclude = "true" (legacy escape hatch)
        - decommission-date-detected is set (already in pipeline)
        - disposition = "delete"   AND date-reviewed + 90d  > today (owner confirmed)
        - disposition = "extend"   AND date-extended        > today
        - disposition = "exempted" AND date-declared + 180d > today

    A resource is re-included (and its disposition reset to "delete") if any expiry
    passes, OR if the owner sets disposition = "extend" with a new date-extended.

    IMPORTANT: this runbook does NOT delete resources. disposition = "delete" is
    recorded but never acted on; the execution layer is deferred.

.PARAMETER DryRun
    If $true, only reports what would be tagged. Default: $true.

.PARAMETER Scope
    phase1 = Disks, NICs, PIPs, NSGs (ARG-sufficient). Default.
    phase2 = phase1 + VMs, App Service Plans, Snapshots (requires Activity Log).
    all    = alias for phase2.

.PARAMETER OwnerTagSource
    Tag name (on resource -> RG -> subscription) from which to derive decommission-owner.
    Default: "owner".

.PARAMETER ManagementGroupId
    Management Group ID to scan. Overrides -Subscriptions if set.

.PARAMETER Subscriptions
    Array of subscription IDs. If empty and no MG, scans all accessible subscriptions.

.PARAMETER IdleWindowDays
    Minimum days a VM must be deallocated to be flagged. Default: 30. Set 0 to disable.

.PARAMETER StaleWindowDays
    Minimum age of a snapshot to be flagged. Default: 90 days.

.PARAMETER DeleteApprovalMaxAgeDays
    How long a "delete" disposition remains valid. Default: 90 days.
    After this, the disposition is cleared and the resource re-enters review.

.PARAMETER ExtensionMaxDays
    Maximum value of (date-extended - date-reviewed). Default: 90 days.
    Extensions beyond this are capped at write time and logged as warnings.

.PARAMETER ExemptedMaxAgeDays
    How long an "exempted" disposition remains valid. Default: 180 days.

.PARAMETER ExcludeResourceGroups
    Array of RG names to skip.

.PARAMETER ExcludeTagName
    Tag name whose "true" value excludes a resource. Default: "decommission-exclude".

.PARAMETER ExportPath
    Where to write the JSON export. If empty, resolves a cross-platform temp dir.

.NOTES
    Version: 1.3.0
    Requires: Az.Accounts, Az.ResourceGraph, Az.Resources, Az.Monitor (for IdleWindowDays > 0)

    Changelog (v1.2.1 -> v1.3.0):
      BREAKING — taxonomy consolidation to the nine-tag spec:
        REMOVED: decommission-state            (derivable from other tags; failed derivability test)
        REMOVED: decommission-candidate        (redundant with date-detected)
        REMOVED: lifecycle-state               (no longer mirrored)
        REMOVED: lifecycle-reason              (no longer mirrored)
        REMOVED: decommission-detected         (renamed to decommission-date-detected)
        RENAMED: decommission-reviewed (unchanged semantically, but now always paired with date-reviewed)
        NEW:     decommission-date-detected    (replaces decommission-detected)
        NEW:     decommission-date-reviewed    (owner writes when flipping reviewed=true)
        NEW:     decommission-date-extended    (owner writes when disposition=extend)
        NEW:     decommission-date-declared    (owner writes when disposition=exempted)
        NEW:     decommission-exempted-reason  (replaces lifecycle-exempt-reason)
        CHANGED: decommission-disposition defaults to "delete" (script-set);
                 owner can overwrite with "extend" | "exempted"
                 (removed "keep"; "exempted" absorbs the old lifecycle-state=exempt semantic)

      FUNCTIONAL:
        NEW: three-way expiry enforcement
             - delete:   date-reviewed + 90d
             - extend:   date-extended (capped at +90d from date-reviewed)
             - exempted: date-declared + 180d
        NEW: on any expiry, disposition+companion tags are cleared, reviewed reset to "false",
             date-detected refreshed. Resource re-enters pending-review.
        NEW: disposition breakdown KPI now reports four buckets:
             awaiting-delete / extend-active / exempted / other
        NEW: workflow-state derivation is computed; no state tag is written.

      DROPPED:
        - TagMode parameter (legacy/typed/dual) — only one taxonomy exists now.
        - MigrateLegacyTags helper — migration is a one-time operation not bundled here.

    Changelog (v1.2.0 -> v1.2.1):
      - FIX: ExportPath default is cross-platform.

    (Earlier changelog entries retained in v1.2.1; not duplicated here.)
#>

param(
    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $true,

    [Parameter(Mandatory = $false)]
    [ValidateSet("phase1", "phase2", "all")]
    [string]$Scope = "phase1",

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
    [int]$DeleteApprovalMaxAgeDays = 90,

    [Parameter(Mandatory = $false)]
    [int]$ExtensionMaxDays = 90,

    [Parameter(Mandatory = $false)]
    [int]$ExemptedMaxAgeDays = 180,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeResourceGroups = @(),

    [Parameter(Mandatory = $false)]
    [string]$ExcludeTagName = "decommission-exclude",

    [Parameter(Mandatory = $false)]
    [string]$ExportPath = ""
)

$SCRIPT_VERSION = "1.3.0"

#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
}

function Resolve-DefaultExportDirectory {
    $candidates = @(
        $env:TEMP,
        $env:TMPDIR,
        $env:TMP,
        [System.IO.Path]::GetTempPath(),
        "/tmp",
        (Get-Location).Path
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique

    foreach ($candidate in $candidates) {
        try {
            if (-not (Test-Path -LiteralPath $candidate -PathType Container)) {
                New-Item -Path $candidate -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }
            return $candidate
        }
        catch { continue }
    }
    return $null
}

function Invoke-ArgPaged {
    param(
        [string]$Query,
        [string]$ManagementGroupId,
        [string[]]$Subscriptions,
        [int]$PageSize = 1000,
        [int]$MaxPages = 100
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
                $rows = @($response.Data)
                $skipToken = $response.SkipToken
            } else {
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
    param([object]$Value, [int]$Default = 0)
    $scalar = Get-FirstNonEmptyString -Value $Value
    if ($null -eq $scalar) { return $Default }
    $parsed = 0
    if ([int]::TryParse($scalar, [ref]$parsed)) { return $parsed }
    return $Default
}

# --- Owner derivation -------------------------------------------------------
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

function Resolve-DecommissionOwner {
    param([object]$Resource, [string]$OwnerTagSource)

    if ($Resource.PSObject.Properties.Name -contains 'tags' -and $Resource.tags) {
        $tagObj = $Resource.tags
        if ($tagObj.PSObject.Properties.Name -contains $OwnerTagSource) {
            $v = $tagObj.$OwnerTagSource
            if ($v) { return $v }
        }
    }

    $subscriptionId = Get-FirstNonEmptyString -Value $Resource.subscriptionId
    $resourceGroup  = Get-FirstNonEmptyString -Value $Resource.resourceGroup

    if ($subscriptionId -and $resourceGroup) {
        $rgOwner = Get-RgOwner -SubscriptionId $subscriptionId -ResourceGroup $resourceGroup -OwnerTagSource $OwnerTagSource
        if ($rgOwner) { return $rgOwner }
    }

    if ($subscriptionId -and $script:SubOwnerCache.ContainsKey($subscriptionId)) {
        $subOwner = $script:SubOwnerCache[$subscriptionId]
        if ($subOwner) { return $subOwner }
    }

    return "unresolved"
}

# --- Tag application --------------------------------------------------------

function Add-DecommissionTags {
    # Writes the five script-owned tags on a newly detected resource.
    # disposition defaults to "delete" — the owner can overwrite it with "extend"
    # or "exempted". Owner-owned tags (reviewed=true, date-reviewed, date-extended,
    # date-declared, exempted-reason) are NEVER written by the script.
    param(
        [string]$ResourceId,
        [string]$Reason,
        [string]$Owner,
        [bool]$DryRun
    )

    $today = Get-Date -Format "yyyy-MM-dd"
    $tags = @{
        "decommission-reviewed"      = "false"
        "decommission-disposition"   = "delete"
        "decommission-owner"         = if ($Owner) { $Owner } else { "unresolved" }
        "decommission-reason"        = $Reason
        "decommission-date-detected" = $today
    }

    if ($DryRun) {
        Write-Log "[DRY RUN] Would tag: $ResourceId (Reason: $Reason, Owner: $Owner)" -Level "INFO"
        return $true
    }

    try {
        $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop
        $existingTags = $resource.Tags
        if ($null -eq $existingTags) { $existingTags = @{} }

        # Merge: never overwrite existing keys. This preserves owner-set values
        # (reviewed=true, disposition, any date-reviewed, etc.) across re-scans.
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

function Reset-ExpiredDisposition {
    # Used by the expiry scans. Clears all owner-owned disposition tags, resets
    # reviewed to "false", restores disposition to "delete" (script default), and
    # refreshes date-detected. The resource re-enters awaiting-delete (unreviewed).
    param(
        [string]$ResourceId,
        [string]$ExpiryReason,
        [bool]$DryRun
    )

    $today = Get-Date -Format "yyyy-MM-dd"
    if ($DryRun) {
        Write-Log "[DRY RUN] Would reset expired disposition: $ResourceId ($ExpiryReason)" -Level "INFO"
        return $true
    }

    try {
        $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop
        $existingTags = $resource.Tags
        if ($null -eq $existingTags) { $existingTags = @{} }

        # Clear owner-owned disposition tags
        foreach ($ownerTag in @(
            "decommission-disposition",
            "decommission-date-reviewed",
            "decommission-date-extended",
            "decommission-date-declared",
            "decommission-exempted-reason"
        )) {
            if ($existingTags.ContainsKey($ownerTag)) {
                $existingTags.Remove($ownerTag) | Out-Null
            }
        }

        # Reset script-owned state to "fresh candidate"
        $existingTags["decommission-reviewed"]      = "false"
        $existingTags["decommission-disposition"]   = "delete"
        $existingTags["decommission-date-detected"] = $today

        Set-AzResource -ResourceId $ResourceId -Tag $existingTags -Force -ErrorAction Stop | Out-Null
        Write-Log "Reset expired disposition: $ResourceId ($ExpiryReason)" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to reset $ResourceId : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

# --- VM deallocation age via Activity Log -----------------------------------

function Test-VmDeallocatedLongerThan {
    param([object]$Vm, [int]$IdleWindowDays)

    if ($IdleWindowDays -le 0) { return $true }

    try {
        $currentCtx = Get-AzContext
        if ($currentCtx.Subscription.Id -ne $Vm.subscriptionId) {
            Set-AzContext -SubscriptionId $Vm.subscriptionId -ErrorAction Stop | Out-Null
        }

        $windowStart = (Get-Date).AddDays(-90)
        $events = Get-AzActivityLog -ResourceId $Vm.id -StartTime $windowStart -WarningAction SilentlyContinue -ErrorAction Stop |
            Where-Object { $_.OperationName.Value -eq 'Microsoft.Compute/virtualMachines/deallocate/action' -and $_.Status.Value -eq 'Succeeded' } |
            Sort-Object EventTimestamp -Descending

        if (-not $events -or $events.Count -eq 0) {
            return $IdleWindowDays -le 90
        }

        $lastDeallocate = $events[0].EventTimestamp
        $ageDays = ((Get-Date) - $lastDeallocate).TotalDays
        return $ageDays -ge $IdleWindowDays
    }
    catch {
        Write-Log "Could not determine deallocation age for $($Vm.id): $($_.Exception.Message). Excluding from tagging." -Level "WARN"
        return $false
    }
}

#endregion

#region Main Execution

$scriptStartTime = Get-Date

Write-Log "============================================================"
Write-Log "     DECOMMISSION CANDIDATE TAGGER (v$SCRIPT_VERSION)"
Write-Log "============================================================"
Write-Log ""
Write-Log "CONFIGURATION:"
Write-Log "  DryRun Mode:              $DryRun $(if ($DryRun) { '(no changes will be made)' } else { '*** LIVE MODE - TAGS WILL BE APPLIED ***' })"
Write-Log "  Scope:                    $Scope"
Write-Log "  OwnerTagSource:           $OwnerTagSource"
Write-Log "  Idle Window:              $IdleWindowDays days $(if ($IdleWindowDays -eq 0) { '(disabled)' })"
Write-Log "  Stale Window:             $StaleWindowDays days"
Write-Log "  Delete Approval Max Age:  $DeleteApprovalMaxAgeDays days"
Write-Log "  Extension Max Days:       $ExtensionMaxDays days"
Write-Log "  Exempted Max Age:         $ExemptedMaxAgeDays days"
Write-Log "  Exclude Tag:              $ExcludeTagName"
Write-Log "  Exclude RGs:              $(if ($ExcludeResourceGroups.Count -gt 0) { $ExcludeResourceGroups -join ', ' } else { '(none)' })"
Write-Log ""
Write-Log "SCOPE:"
if ($ManagementGroupId) {
    Write-Log "  Management Group:         $ManagementGroupId"
} elseif ($Subscriptions.Count -gt 0) {
    Write-Log "  Subscriptions:            $($Subscriptions.Count) specified"
    foreach ($sub in $Subscriptions) { Write-Log "    - $sub" }
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
Write-Log "  Excluded by disposition:  delete (owner confirmed within 90d), extend (before date-extended), exempted (within 180d)"
Write-Log "  Re-included:              Any disposition whose expiry has passed (reset to delete default)"
Write-Log ""

# --- KQL filter fragments (v1.3.0 nine-tag spec) ---------------------------
$today = Get-Date -Format "yyyy-MM-dd"
$deleteExpiryDate   = (Get-Date).AddDays(-$DeleteApprovalMaxAgeDays).ToString("yyyy-MM-dd")
$exemptedExpiryDate = (Get-Date).AddDays(-$ExemptedMaxAgeDays).ToString("yyyy-MM-dd")

$excludeTagFilter = "| where isnull(tags['$ExcludeTagName']) or tags['$ExcludeTagName'] != 'true'"

# Skip resources where the owner's disposition is still within its validity window.
# Three cases, all with explicit date bounds — no implicit forever-valid dispositions.
$activeDispositionFilter = @"
| where not (
    (tostring(tags['decommission-disposition']) == 'delete'
      and todatetime(tostring(tags['decommission-date-reviewed'])) >= datetime('$deleteExpiryDate'))
    or (tostring(tags['decommission-disposition']) == 'extend'
      and todatetime(tostring(tags['decommission-date-extended'])) > now())
    or (tostring(tags['decommission-disposition']) == 'exempted'
      and todatetime(tostring(tags['decommission-date-declared'])) >= datetime('$exemptedExpiryDate'))
  )
"@

# Skip resources already tagged as pending-review (date-detected set, no disposition yet).
# These are handled by the existing review cycle; do not re-tag.
$alreadyPendingFilter = @"
| where isnull(tags['decommission-date-detected'])
"@

# Determine class list from Scope
$phase1Classes = @("UnattachedDisks", "OrphanNICs", "OrphanPIPs", "OrphanNSGs")
$phase2Classes = $phase1Classes + @("DeallocatedVMs", "EmptyASPs", "StaleSnapshots")
$activeClasses = switch ($Scope) {
    "phase1" { $phase1Classes }
    "phase2" { $phase2Classes }
    "all"    { $phase2Classes }
}
Write-Log "ACTIVE CLASSES: $($activeClasses -join ', ')"
Write-Log ""

# Track results
$summary = @{}
foreach ($c in @("UnattachedDisks","OrphanNICs","OrphanPIPs","OrphanNSGs","DeallocatedVMs","EmptyASPs","StaleSnapshots","ExpiredDelete","ExpiredExtend","ExpiredExempted")) {
    $summary[$c] = @{ Found = 0; Tagged = 0; Skipped = 0 }
}

$costEstimates = @{
    "UnattachedDisks" = 0.0
    "OrphanPIPs"      = 0.0
    "DeallocatedVMs"  = 0.0
    "EmptyASPs"       = 0.0
    "StaleSnapshots"  = 0.0
}

function Get-SubscriptionName {
    param([string]$SubscriptionId)
    $sub = $subsInScope | Where-Object { $_.subscriptionId -eq $SubscriptionId }
    if ($sub) { return $sub.name }
    return $SubscriptionId
}

function Get-EstimatedMonthlyCost {
    param([string]$ResourceType, [object]$Resource)

    switch ($ResourceType) {
        "Disk" {
            $sizeGB = Convert-ToIntSafe -Value $Resource.diskSizeGB -Default 0
            $sku = $Resource.sku_name
            if ($sku -match "Premium") {
                if ($sizeGB -le 32)   { return 5.28 }
                elseif ($sizeGB -le 64)   { return 10.21 }
                elseif ($sizeGB -le 128)  { return 19.71 }
                elseif ($sizeGB -le 256)  { return 38.02 }
                elseif ($sizeGB -le 512)  { return 73.22 }
                elseif ($sizeGB -le 1024) { return 140.74 }
                elseif ($sizeGB -le 2048) { return 270.34 }
                else                      { return 519.48 }
            } elseif ($sku -match "StandardSSD") {
                if ($sizeGB -le 32)   { return 2.40 }
                elseif ($sizeGB -le 64)   { return 4.80 }
                elseif ($sizeGB -le 128)  { return 9.60 }
                elseif ($sizeGB -le 256)  { return 18.43 }
                elseif ($sizeGB -le 512)  { return 35.33 }
                elseif ($sizeGB -le 1024) { return 67.58 }
                else                      { return 129.54 }
            } else {
                return $sizeGB * 0.04
            }
        }
        "PublicIP" {
            $sku = $Resource.sku_name
            if ($sku -eq "Standard") { return 3.65 } else { return 2.63 }
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

# Reason vocabulary (owner-facing): "orphaned" | "idle" | "stale"
# Detector vocabulary (script-facing; reserved for future splitting): class-specific codes

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
$activeDispositionFilter
$alreadyPendingFilter
| project id, name, resourceGroup, location, subscriptionId, tags, sku_name=sku.name, diskSizeGB=properties.diskSizeGB
"@
    $disks = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["UnattachedDisks"].Found = $disks.Count
    Write-Log "    Found: $($disks.Count) unattached disks (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "UnattachedDisks" -Resources $disks -ExtraFields @{ "SKU" = "sku_name"; "Size (GB)" = "diskSizeGB" }

    foreach ($disk in $disks) {
        $owner = Resolve-DecommissionOwner -Resource $disk -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "Disk" -Resource $disk
        $ok    = Add-DecommissionTags -ResourceId $disk.id -Reason "orphaned" -Owner $owner -DryRun $DryRun
        if ($ok) { $summary["UnattachedDisks"].Tagged++ }
        $costEstimates["UnattachedDisks"] += $cost
        Add-ExportRecord -Category "UnattachedDisks" -Resource $disk -Reason "orphaned" -Owner $owner -EstCostMonth $cost
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
$activeDispositionFilter
$alreadyPendingFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
    $nics = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["OrphanNICs"].Found = $nics.Count
    Write-Log "    Found: $($nics.Count) orphan NICs (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "OrphanNICs" -Resources $nics -ExtraFields @{}

    foreach ($nic in $nics) {
        $owner = Resolve-DecommissionOwner -Resource $nic -OwnerTagSource $OwnerTagSource
        $ok    = Add-DecommissionTags -ResourceId $nic.id -Reason "orphaned" -Owner $owner -DryRun $DryRun
        if ($ok) { $summary["OrphanNICs"].Tagged++ }
        Add-ExportRecord -Category "OrphanNICs" -Resource $nic -Reason "orphaned" -Owner $owner -EstCostMonth 0.0
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
$activeDispositionFilter
$alreadyPendingFilter
| project id, name, resourceGroup, location, subscriptionId, tags, sku_name=sku.name
"@
    $pips = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["OrphanPIPs"].Found = $pips.Count
    Write-Log "    Found: $($pips.Count) orphan Public IPs (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "OrphanPIPs" -Resources $pips -ExtraFields @{ "SKU" = "sku_name" }

    foreach ($pip in $pips) {
        $owner = Resolve-DecommissionOwner -Resource $pip -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "PublicIP" -Resource $pip
        $ok    = Add-DecommissionTags -ResourceId $pip.id -Reason "orphaned" -Owner $owner -DryRun $DryRun
        if ($ok) { $summary["OrphanPIPs"].Tagged++ }
        $costEstimates["OrphanPIPs"] += $cost
        Add-ExportRecord -Category "OrphanPIPs" -Resource $pip -Reason "orphaned" -Owner $owner -EstCostMonth $cost
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
$activeDispositionFilter
$alreadyPendingFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
    $nsgs = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["OrphanNSGs"].Found = $nsgs.Count
    Write-Log "    Found: $($nsgs.Count) orphan NSGs (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "OrphanNSGs" -Resources $nsgs -ExtraFields @{}

    foreach ($nsg in $nsgs) {
        $owner = Resolve-DecommissionOwner -Resource $nsg -OwnerTagSource $OwnerTagSource
        $ok    = Add-DecommissionTags -ResourceId $nsg.id -Reason "orphaned" -Owner $owner -DryRun $DryRun
        if ($ok) { $summary["OrphanNSGs"].Tagged++ }
        Add-ExportRecord -Category "OrphanNSGs" -Resource $nsg -Reason "orphaned" -Owner $owner -EstCostMonth 0.0
    }
    Write-Log ""
}

#endregion

#region Phase 2 classes (idle / stale)

if ("DeallocatedVMs" -in $activeClasses) {
    Write-Log "[DEALLOCATED VIRTUAL MACHINES]"
    if ($IdleWindowDays -gt 0) {
        Write-Log "    Criteria: VM deallocated for >= $IdleWindowDays days (Activity Log corroborated)"
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
$activeDispositionFilter
$alreadyPendingFilter
| project id, name, resourceGroup, location, subscriptionId, tags, vmSize=properties.hardwareProfile.vmSize
"@
    $vmsAll = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions

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
        $owner = Resolve-DecommissionOwner -Resource $vm -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "VM" -Resource $vm
        $ok    = Add-DecommissionTags -ResourceId $vm.id -Reason "idle" -Owner $owner -DryRun $DryRun
        if ($ok) { $summary["DeallocatedVMs"].Tagged++ }
        $costEstimates["DeallocatedVMs"] += $cost
        Add-ExportRecord -Category "DeallocatedVMs" -Resource $vm -Reason "idle" -Owner $owner -EstCostMonth $cost
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
$activeDispositionFilter
$alreadyPendingFilter
| project id, name, resourceGroup, location, subscriptionId, tags, sku_name=sku.name
"@
    $asps = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["EmptyASPs"].Found = $asps.Count
    Write-Log "    Found: $($asps.Count) empty App Service Plans (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "EmptyASPs" -Resources $asps -ExtraFields @{ "SKU" = "sku_name" }

    foreach ($asp in $asps) {
        $owner = Resolve-DecommissionOwner -Resource $asp -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "AppServicePlan" -Resource $asp
        $ok    = Add-DecommissionTags -ResourceId $asp.id -Reason "idle" -Owner $owner -DryRun $DryRun
        if ($ok) { $summary["EmptyASPs"].Tagged++ }
        $costEstimates["EmptyASPs"] += $cost
        Add-ExportRecord -Category "EmptyASPs" -Resource $asp -Reason "idle" -Owner $owner -EstCostMonth $cost
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
$activeDispositionFilter
$alreadyPendingFilter
| project id, name, resourceGroup, location, subscriptionId, tags, diskSizeGB=properties.diskSizeGB, timeCreated=properties.timeCreated
"@
    $snapshots = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
    $scanDuration = ((Get-Date) - $scanStart).TotalSeconds
    $summary["StaleSnapshots"].Found = $snapshots.Count
    Write-Log "    Found: $($snapshots.Count) stale snapshots (scan took $([math]::Round($scanDuration, 2))s)"
    Write-ResourceTable -Category "StaleSnapshots" -Resources $snapshots -ExtraFields @{ "Size (GB)" = "diskSizeGB"; "Created" = "timeCreated" }

    foreach ($snapshot in $snapshots) {
        $owner = Resolve-DecommissionOwner -Resource $snapshot -OwnerTagSource $OwnerTagSource
        $cost  = Get-EstimatedMonthlyCost -ResourceType "Snapshot" -Resource $snapshot
        $ok    = Add-DecommissionTags -ResourceId $snapshot.id -Reason "stale" -Owner $owner -DryRun $DryRun
        if ($ok) { $summary["StaleSnapshots"].Tagged++ }
        $costEstimates["StaleSnapshots"] += $cost
        Add-ExportRecord -Category "StaleSnapshots" -Resource $snapshot -Reason "stale" -Owner $owner -EstCostMonth $cost
    }
    Write-Log ""
}

#endregion

#region Expiry scans (three parallel scans, one per disposition value)

# Each expiry scan behaves identically: find resources whose disposition window
# has passed, clear the disposition tags, reset reviewed to "false", refresh
# date-detected. The resource re-enters pending-review.

# 1. Expired delete approvals (disposition = delete, date-reviewed older than 90d)
Write-Log "[EXPIRY SCAN - delete approvals]"
Write-Log "    Criteria: disposition = 'delete' AND reviewed = 'true' AND date-reviewed older than $DeleteApprovalMaxAgeDays days"
$scanStart = Get-Date
$query = @"
resources
| where tostring(tags['decommission-disposition']) == 'delete'
| where tostring(tags['decommission-reviewed']) == 'true'
| extend reviewedAt = todatetime(tostring(tags['decommission-date-reviewed']))
| where isnull(reviewedAt) or reviewedAt < datetime('$deleteExpiryDate')
$excludeRgFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
$expiredDelete = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["ExpiredDelete"].Found = $expiredDelete.Count
Write-Log "    Found: $($expiredDelete.Count) expired delete approvals (scan took $([math]::Round($scanDuration, 2))s)"
foreach ($r in $expiredDelete) {
    $ok = Reset-ExpiredDisposition -ResourceId $r.id -ExpiryReason "delete-approval-expired" -DryRun $DryRun
    if ($ok) { $summary["ExpiredDelete"].Tagged++ }
    Add-ExportRecord -Category "ExpiredDelete" -Resource $r -Reason "delete-approval-expired" -Owner "review-required" -EstCostMonth 0.0
}
Write-Log ""

# 2. Expired extensions (disposition = extend, date-extended in the past)
Write-Log "[EXPIRY SCAN - extensions]"
Write-Log "    Criteria: disposition = 'extend' AND date-extended < today"
$scanStart = Get-Date
$query = @"
resources
| where tostring(tags['decommission-disposition']) == 'extend'
| extend extendedUntil = todatetime(tostring(tags['decommission-date-extended']))
| where isnull(extendedUntil) or extendedUntil <= now()
$excludeRgFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
$expiredExtend = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["ExpiredExtend"].Found = $expiredExtend.Count
Write-Log "    Found: $($expiredExtend.Count) expired extensions (scan took $([math]::Round($scanDuration, 2))s)"
foreach ($r in $expiredExtend) {
    $ok = Reset-ExpiredDisposition -ResourceId $r.id -ExpiryReason "extension-expired" -DryRun $DryRun
    if ($ok) { $summary["ExpiredExtend"].Tagged++ }
    Add-ExportRecord -Category "ExpiredExtend" -Resource $r -Reason "extension-expired" -Owner "review-required" -EstCostMonth 0.0
}
Write-Log ""

# 3. Expired exemptions (disposition = exempted, date-declared older than 180d)
Write-Log "[EXPIRY SCAN - exemptions]"
Write-Log "    Criteria: disposition = 'exempted' AND date-declared older than $ExemptedMaxAgeDays days"
$scanStart = Get-Date
$query = @"
resources
| where tostring(tags['decommission-disposition']) == 'exempted'
| extend declaredAt = todatetime(tostring(tags['decommission-date-declared']))
| where isnull(declaredAt) or declaredAt < datetime('$exemptedExpiryDate')
$excludeRgFilter
| project id, name, resourceGroup, location, subscriptionId, tags
"@
$expiredExempted = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["ExpiredExempted"].Found = $expiredExempted.Count
Write-Log "    Found: $($expiredExempted.Count) expired exemptions (scan took $([math]::Round($scanDuration, 2))s)"
foreach ($r in $expiredExempted) {
    $ok = Reset-ExpiredDisposition -ResourceId $r.id -ExpiryReason "exemption-expired" -DryRun $DryRun
    if ($ok) { $summary["ExpiredExempted"].Tagged++ }
    Add-ExportRecord -Category "ExpiredExempted" -Resource $r -Reason "exemption-expired" -Owner "review-required" -EstCostMonth 0.0
}
Write-Log ""

#endregion

#region Disposition breakdown (estate-wide snapshot of the derived workflow state)

# Workflow state is DERIVED from the tag combination, not stored. This scan
# computes the state on the fly for governance reporting.
Write-Log "[DISPOSITION BREAKDOWN - estate-wide snapshot]"
$scanStart = Get-Date
$dispositionQuery = @"
resources
| where isnotnull(tags['decommission-date-detected'])
$excludeRgFilter
| extend reviewed    = tostring(tags['decommission-reviewed'])
| extend disposition = tostring(tags['decommission-disposition'])
| extend bucket = case(
    disposition == 'delete',   'awaiting-delete',
    disposition == 'extend',   'extend-active',
    disposition == 'exempted', 'exempted',
    'other'
  )
| summarize count = count() by bucket
"@
$dispositionBreakdown = Get-ResourceGraphResults -Query $dispositionQuery -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds

$dispositionTotals = @{
    "awaiting-delete"         = 0
    "extend-active"           = 0
    "exempted"                = 0
    "other"                   = 0
}
foreach ($row in $dispositionBreakdown) {
    $bucket = [string]$row.bucket
    $count  = Convert-ToIntSafe -Value $row.count -Default 0
    if ($dispositionTotals.ContainsKey($bucket)) {
        $dispositionTotals[$bucket] = $count
    }
}

Write-Log "    Scan took $([math]::Round($scanDuration, 2))s"
Write-Log "    +------------------------------+---------+"
Write-Log "    | Workflow state               |  Count  |"
Write-Log "    +------------------------------+---------+"
$orderedBuckets = @("awaiting-delete","extend-active","exempted","other")
$dispositionGrandTotal = 0
foreach ($bucket in $orderedBuckets) {
    $cnt = $dispositionTotals[$bucket]
    $dispositionGrandTotal += $cnt
    $label = $bucket.PadRight(28)
    $cntStr = $cnt.ToString().PadLeft(5)
    Write-Log "    | $label | $cntStr   |"
}
Write-Log "    +------------------------------+---------+"
Write-Log "    | TOTAL                        | $(($dispositionGrandTotal.ToString()).PadLeft(5))   |"
Write-Log "    +------------------------------+---------+"
Write-Log ""

#endregion

#region Summary Report & Export

$scriptEndTime = Get-Date
$totalDuration = ($scriptEndTime - $scriptStartTime).TotalSeconds

Write-Log "============================================================"
Write-Log "                      SUMMARY REPORT"
Write-Log "============================================================"
Write-Log ""
Write-Log "SCAN RESULTS (this run):"
Write-Log "    +----------------------------+---------+---------+----------------+"
Write-Log "    | Category                   |  Found  |  Tagged | Est. Cost/mo   |"
Write-Log "    +----------------------------+---------+---------+----------------+"

$totalFound = 0
$totalTagged = 0
$totalCost = 0.0

$categoryOrder = @("UnattachedDisks","OrphanNICs","OrphanPIPs","OrphanNSGs","DeallocatedVMs","EmptyASPs","StaleSnapshots","ExpiredDelete","ExpiredExtend","ExpiredExempted")
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

$unresolvedCount = ($exportRecords | Where-Object { $_.owner -eq "unresolved" }).Count
$resolvedCount   = $exportRecords.Count - $unresolvedCount
$resolutionPct   = if ($exportRecords.Count -gt 0) { [math]::Round(100.0 * $resolvedCount / $exportRecords.Count, 1) } else { 0.0 }
Write-Log "OWNER RESOLUTION (this run):"
Write-Log "    Resolved:                 $resolvedCount"
Write-Log "    Unresolved:               $unresolvedCount"
Write-Log "    Resolution rate:          $resolutionPct%"
Write-Log ""

Write-Log "POTENTIAL SAVINGS (indicative, West Europe list prices):"
Write-Log "    Estimated Monthly:        EUR $([math]::Round($totalCost, 2).ToString("N2"))"
Write-Log "    Estimated Annual:         EUR $([math]::Round($totalCost * 12, 2).ToString("N2"))"
Write-Log ""

Write-Log "EXECUTION DETAILS:"
Write-Log "    Start Time:               $($scriptStartTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Log "    End Time:                 $($scriptEndTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Log "    Duration:                 $([math]::Round($totalDuration, 2)) seconds"
Write-Log "    Subscriptions:            $($subsInScope.Count) scanned"
Write-Log "    Scope:                    $Scope"
Write-Log "    Script Version:           $SCRIPT_VERSION"
Write-Log ""

# JSON export
if (-not $ExportPath) {
    $exportDir = Resolve-DefaultExportDirectory
    if (-not $exportDir) {
        throw "Could not resolve a writable export directory. Provide -ExportPath explicitly."
    }
    $ExportPath = Join-Path -Path $exportDir -ChildPath "decommission-candidates-$($scriptStartTime.ToString('yyyyMMddHHmmss')).json"
}
$exportEnvelope = [pscustomobject]@{
    schemaVersion         = "1.3"
    scriptVersion         = $SCRIPT_VERSION
    runStartedAt          = $scriptStartTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    runEndedAt            = $scriptEndTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
    dryRun                = $DryRun
    scope                 = $Scope
    idleWindowDays        = $IdleWindowDays
    staleWindowDays       = $StaleWindowDays
    deleteApprovalMaxAge  = $DeleteApprovalMaxAgeDays
    extensionMaxDays      = $ExtensionMaxDays
    exemptedMaxAge        = $ExemptedMaxAgeDays
    subscriptionsScanned  = $subsInScope.Count
    totals                = [pscustomobject]@{
        found              = $totalFound
        tagged             = $totalTagged
        estCostEurMonth    = [math]::Round($totalCost, 2)
        ownerResolvedPct   = $resolutionPct
    }
    dispositionBreakdown  = [pscustomobject]@{
        awaitingDelete        = $dispositionTotals["awaiting-delete"]
        extendActive          = $dispositionTotals["extend-active"]
        exempted              = $dispositionTotals["exempted"]
        other                 = $dispositionTotals["other"]
        total                 = $dispositionGrandTotal
    }
    expiryActivity        = [pscustomobject]@{
        expiredDeleteReset   = $summary["ExpiredDelete"].Tagged
        expiredExtendReset   = $summary["ExpiredExtend"].Tagged
        expiredExemptedReset = $summary["ExpiredExempted"].Tagged
    }
    perCategory           = ($summary.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{
            category = $_.Key
            found    = $_.Value.Found
            tagged   = $_.Value.Tagged
            skipped  = $_.Value.Skipped
        }
    })
    records               = $exportRecords
}

try {
    $exportEnvelope | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
    Write-Log "EXPORT:"
    Write-Log "    Wrote $($exportRecords.Count) records to: $ExportPath"
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
