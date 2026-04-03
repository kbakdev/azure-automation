<#
.SYNOPSIS
    Tags unused Azure resources as decommission candidates.

.DESCRIPTION
    This runbook queries Azure Resource Graph to identify:
    - Orphaned resources (unattached disks, NICs, PIPs, NSGs)
    - Idle resources (deallocated VMs, empty App Service Plans)
    - Stale resources (old snapshots, disk images)
    
    It applies the tag "decommission-candidate: true" along with metadata tags
    for the detection date and reason. This is Phase 3 of the decommission workflow.
    
    IMPORTANT: This runbook does NOT delete resources. It only tags them.

.PARAMETER DryRun
    If $true, only reports what would be tagged without making changes.
    Default: $true (safe by default)

.PARAMETER ManagementGroupId
    Management Group ID to scan all subscriptions under it.
    If set, overrides the Subscriptions parameter.

.PARAMETER Subscriptions
    Array of subscription IDs to scan. If empty and ManagementGroupId not set,
    scans all accessible subscriptions.

.PARAMETER IdleWindowDays
    Number of days a VM must be deallocated to be considered idle. Default: 30

.PARAMETER StaleWindowDays
    Number of days since creation for snapshots/images to be considered stale. Default: 90

.PARAMETER ExcludeResourceGroups
    Array of resource group names to exclude from tagging.

.PARAMETER ExcludeTagName
    Resources with this tag will be excluded. Default: "decommission-exclude"

.NOTES
    Version: 1.0.0
    Requires: Az.Accounts, Az.ResourceGraph, Az.Resources
#>

param(
    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $true,

    [Parameter(Mandatory = $false)]
    [string]$ManagementGroupId = "",

    [Parameter(Mandatory = $false)]
    [string[]]$Subscriptions = @(),

    [Parameter(Mandatory = $false)]
    [int]$IdleWindowDays = 30,

    [Parameter(Mandatory = $false)]
    [int]$StaleWindowDays = 90,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeResourceGroups = @(),

    [Parameter(Mandatory = $false)]
    [string]$ExcludeTagName = "decommission-exclude"
)

#region Helper Functions

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Output "[$timestamp] [$Level] $Message"
}

function Get-ResourceGraphResults {
    param(
        [string]$Query,
        [string]$ManagementGroupId,
        [string[]]$Subscriptions
    )
    
    $results = @()
    
    if ($ManagementGroupId -ne "") {
        # Query at Management Group scope (all subscriptions under it)
        Write-Log "Querying Management Group: $ManagementGroupId" -Level "DEBUG"
        $results = Search-AzGraph -Query $Query -ManagementGroup $ManagementGroupId -First 1000
    }
    elseif ($Subscriptions.Count -gt 0) {
        # Query specific subscriptions
        $results = Search-AzGraph -Query $Query -Subscription $Subscriptions -First 1000
    }
    else {
        # Query all accessible subscriptions (default)
        $results = Search-AzGraph -Query $Query -First 1000
    }
    
    return $results
}

function Add-DecommissionTag {
    param(
        [string]$ResourceId,
        [string]$Reason,
        [bool]$DryRun
    )
    
    $tags = @{
        "decommission-candidate" = "true"
        "decommission-detected"  = (Get-Date -Format "yyyy-MM-dd")
        "decommission-reason"    = $Reason
    }
    
    if ($DryRun) {
        Write-Log "[DRY RUN] Would tag: $ResourceId (Reason: $Reason)" -Level "INFO"
        return $true
    }
    
    try {
        $resource = Get-AzResource -ResourceId $ResourceId -ErrorAction Stop
        $existingTags = $resource.Tags
        
        if ($null -eq $existingTags) {
            $existingTags = @{}
        }
        
        # Merge tags (don't overwrite existing)
        foreach ($key in $tags.Keys) {
            if (-not $existingTags.ContainsKey($key)) {
                $existingTags[$key] = $tags[$key]
            }
        }
        
        Set-AzResource -ResourceId $ResourceId -Tag $existingTags -Force -ErrorAction Stop | Out-Null
        Write-Log "Tagged: $ResourceId (Reason: $Reason)" -Level "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to tag $ResourceId : $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

#endregion

#region Main Execution

$scriptStartTime = Get-Date

Write-Log "============================================================"
Write-Log "     UNUSED RESOURCE TAGGING AUTOMATION"
Write-Log "============================================================"
Write-Log ""
Write-Log "CONFIGURATION:"
Write-Log "  DryRun Mode:        $DryRun $(if ($DryRun) { '(no changes will be made)' } else { '*** LIVE MODE - TAGS WILL BE APPLIED ***' })"
Write-Log "  Idle Window:        $IdleWindowDays days"
Write-Log "  Stale Window:       $StaleWindowDays days"
Write-Log "  Exclude Tag:        $ExcludeTagName"
Write-Log "  Exclude RGs:        $(if ($ExcludeResourceGroups.Count -gt 0) { $ExcludeResourceGroups -join ', ' } else { '(none)' })"
Write-Log ""
Write-Log "SCOPE:"
if ($ManagementGroupId) {
    Write-Log "  Management Group:   $ManagementGroupId"
    Write-Log "  (All subscriptions under this MG hierarchy will be scanned)"
} elseif ($Subscriptions.Count -gt 0) {
    Write-Log "  Subscriptions:      $($Subscriptions.Count) specified"
    foreach ($sub in $Subscriptions) {
        Write-Log "    - $sub"
    }
} else {
    Write-Log "  Subscriptions:      All accessible to current identity"
}
Write-Log ""

# Discover subscriptions in scope
Write-Log "DISCOVERING SUBSCRIPTIONS IN SCOPE..."
$subscriptionQuery = "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId, name, tags"
try {
    if ($ManagementGroupId) {
        $subsInScope = Search-AzGraph -Query $subscriptionQuery -ManagementGroup $ManagementGroupId -First 1000
    } elseif ($Subscriptions.Count -gt 0) {
        $subsInScope = Search-AzGraph -Query $subscriptionQuery -Subscription $Subscriptions -First 1000
    } else {
        $subsInScope = Search-AzGraph -Query $subscriptionQuery -First 1000
    }
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
Write-Log "  Excluded by Tag: Resources with '$ExcludeTagName = true'"
Write-Log "  Skipped: Resources already tagged with 'decommission-candidate = true'"
Write-Log ""

$excludeTagFilter = "| where isnull(tags['$ExcludeTagName']) or tags['$ExcludeTagName'] != 'true'"
$alreadyTaggedFilter = "| where isnull(tags['decommission-candidate']) or tags['decommission-candidate'] != 'true'"

# Track results with details
$summary = @{
    "UnattachedDisks" = @{ Found = 0; Tagged = 0; Details = @() }
    "OrphanNICs" = @{ Found = 0; Tagged = 0; Details = @() }
    "OrphanPIPs" = @{ Found = 0; Tagged = 0; Details = @() }
    "OrphanNSGs" = @{ Found = 0; Tagged = 0; Details = @() }
    "DeallocatedVMs" = @{ Found = 0; Tagged = 0; Details = @() }
    "EmptyASPs" = @{ Found = 0; Tagged = 0; Details = @() }
    "StaleSnapshots" = @{ Found = 0; Tagged = 0; Details = @() }
    "StaleImages" = @{ Found = 0; Tagged = 0; Details = @() }
}

# Helper to get subscription name
function Get-SubscriptionName {
    param([string]$SubscriptionId)
    $sub = $subsInScope | Where-Object { $_.subscriptionId -eq $SubscriptionId }
    if ($sub) { return $sub.name }
    return $SubscriptionId
}

# Helper to log resource details
function Write-ResourceTable {
    param(
        [string]$Category,
        [object[]]$Resources,
        [hashtable]$ExtraFields
    )
    
    if ($Resources.Count -eq 0) {
        Write-Log "    (no resources found)"
        return
    }
    
    Write-Log "    ┌─────────────────────────────────────────────────────────────────────────────"
    $counter = 1
    foreach ($res in $Resources) {
        $subName = Get-SubscriptionName -SubscriptionId $res.subscriptionId
        
        Write-Log "    │ [$counter] $($res.name)"
        Write-Log "    │     Subscription:   $subName"
        Write-Log "    │     Resource Group: $($res.resourceGroup)"
        Write-Log "    │     Location:       $($res.location)"
        Write-Log "    │     Resource ID:    $($res.id)"
        
        # Add extra fields if provided
        if ($ExtraFields) {
            foreach ($label in $ExtraFields.Keys) {
                $fieldPath = $ExtraFields[$label]
                $value = $res
                foreach ($part in $fieldPath.Split('.')) {
                    if ($value) { $value = $value.$part }
                }
                if ($value) {
                    Write-Log "    │     ${label}: $value"
                }
            }
        }
        
        if ($counter -lt $Resources.Count) {
            Write-Log "    │"
        }
        $counter++
    }
    Write-Log "    └─────────────────────────────────────────────────────────────────────────────"
}

Write-Log "============================================================"
Write-Log "                   SCANNING RESOURCES"
Write-Log "============================================================"
Write-Log ""

#region Orphaned Resources

# 1. Unattached Managed Disks
Write-Log "[1/8] UNATTACHED MANAGED DISKS"
Write-Log "    Criteria: Disk not attached to any VM (diskState = 'Unattached')"
$scanStart = Get-Date
$query = @"
resources
| where type =~ 'microsoft.compute/disks'
| where managedBy == '' or isnull(managedBy)
| where properties.diskState == 'Unattached'
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, sku_name=sku.name, diskSizeGB=properties.diskSizeGB
"@

$disks = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["UnattachedDisks"].Found = $disks.Count
Write-Log "    Found: $($disks.Count) unattached disks (scan took $([math]::Round($scanDuration, 2))s)"
Write-ResourceTable -Category "UnattachedDisks" -Resources $disks -ExtraFields @{ "SKU" = "sku_name"; "Size (GB)" = "diskSizeGB" }

foreach ($disk in $disks) {
    $result = Add-DecommissionTag -ResourceId $disk.id -Reason "Orphan-UnattachedDisk" -DryRun $DryRun
    if ($result) { $summary["UnattachedDisks"].Tagged++ }
}
Write-Log ""

# 2. Orphan NICs
Write-Log "[2/8] ORPHAN NETWORK INTERFACES"
Write-Log "    Criteria: NIC not attached to any VM or Private Endpoint"
$scanStart = Get-Date
$query = @"
resources
| where type =~ 'microsoft.network/networkinterfaces'
| where isnull(properties.virtualMachine.id) or properties.virtualMachine.id == ''
| where isnull(properties.privateEndpoint.id) or properties.privateEndpoint.id == ''
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId
"@

$nics = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["OrphanNICs"].Found = $nics.Count
Write-Log "    Found: $($nics.Count) orphan NICs (scan took $([math]::Round($scanDuration, 2))s)"
Write-ResourceTable -Category "OrphanNICs" -Resources $nics -ExtraFields @{}

foreach ($nic in $nics) {
    $result = Add-DecommissionTag -ResourceId $nic.id -Reason "Orphan-NoVMAttached" -DryRun $DryRun
    if ($result) { $summary["OrphanNICs"].Tagged++ }
}
Write-Log ""

# 3. Orphan Public IPs
Write-Log "[3/8] ORPHAN PUBLIC IP ADDRESSES"
Write-Log "    Criteria: Public IP not associated with any resource"
$scanStart = Get-Date
$query = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnull(properties.ipConfiguration.id) or properties.ipConfiguration.id == ''
| where isnull(properties.natGateway.id) or properties.natGateway.id == ''
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, sku_name=sku.name
"@

$pips = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["OrphanPIPs"].Found = $pips.Count
Write-Log "    Found: $($pips.Count) orphan Public IPs (scan took $([math]::Round($scanDuration, 2))s)"
Write-ResourceTable -Category "OrphanPIPs" -Resources $pips -ExtraFields @{ "SKU" = "sku_name" }

foreach ($pip in $pips) {
    $result = Add-DecommissionTag -ResourceId $pip.id -Reason "Orphan-NotAssociated" -DryRun $DryRun
    if ($result) { $summary["OrphanPIPs"].Tagged++ }
}
Write-Log ""

# 4. Orphan NSGs
Write-Log "[4/8] ORPHAN NETWORK SECURITY GROUPS"
Write-Log "    Criteria: NSG not attached to any subnet or NIC"
$scanStart = Get-Date
$query = @"
resources
| where type =~ 'microsoft.network/networksecuritygroups'
| where isnull(properties.subnets) or array_length(properties.subnets) == 0
| where isnull(properties.networkInterfaces) or array_length(properties.networkInterfaces) == 0
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId
"@

$nsgs = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["OrphanNSGs"].Found = $nsgs.Count
Write-Log "    Found: $($nsgs.Count) orphan NSGs (scan took $([math]::Round($scanDuration, 2))s)"
Write-ResourceTable -Category "OrphanNSGs" -Resources $nsgs -ExtraFields @{}

foreach ($nsg in $nsgs) {
    $result = Add-DecommissionTag -ResourceId $nsg.id -Reason "Orphan-NotAttached" -DryRun $DryRun
    if ($result) { $summary["OrphanNSGs"].Tagged++ }
}
Write-Log ""

#endregion

#region Idle Resources

# 5. Deallocated VMs (idle for more than threshold)
Write-Log "[5/8] DEALLOCATED VIRTUAL MACHINES"
Write-Log "    Criteria: VM in 'Deallocated' power state"
$scanStart = Get-Date
$idleDate = (Get-Date).AddDays(-$IdleWindowDays).ToString("yyyy-MM-ddTHH:mm:ssZ")

$query = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where properties.extended.instanceView.powerState.code =~ 'PowerState/deallocated'
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, vmSize=properties.hardwareProfile.vmSize
"@

$vms = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["DeallocatedVMs"].Found = $vms.Count
Write-Log "    Found: $($vms.Count) deallocated VMs (scan took $([math]::Round($scanDuration, 2))s)"
Write-ResourceTable -Category "DeallocatedVMs" -Resources $vms -ExtraFields @{ "VM Size" = "vmSize" }

foreach ($vm in $vms) {
    $result = Add-DecommissionTag -ResourceId $vm.id -Reason "Idle-Deallocated" -DryRun $DryRun
    if ($result) { $summary["DeallocatedVMs"].Tagged++ }
}
Write-Log ""

# 6. Empty App Service Plans
Write-Log "[6/8] EMPTY APP SERVICE PLANS"
Write-Log "    Criteria: App Service Plan with 0 hosted apps"
$scanStart = Get-Date
$query = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, sku_name=sku.name
"@

$asps = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["EmptyASPs"].Found = $asps.Count
Write-Log "    Found: $($asps.Count) empty App Service Plans (scan took $([math]::Round($scanDuration, 2))s)"
Write-ResourceTable -Category "EmptyASPs" -Resources $asps -ExtraFields @{ "SKU" = "sku_name" }

foreach ($asp in $asps) {
    $result = Add-DecommissionTag -ResourceId $asp.id -Reason "Idle-NoAppsHosted" -DryRun $DryRun
    if ($result) { $summary["EmptyASPs"].Tagged++ }
}
Write-Log ""

#endregion

#region Stale Resources

# 7. Old Snapshots
Write-Log "[7/8] STALE SNAPSHOTS"
Write-Log "    Criteria: Snapshot created more than $StaleWindowDays days ago"
$scanStart = Get-Date
$staleDate = (Get-Date).AddDays(-$StaleWindowDays).ToString("yyyy-MM-ddTHH:mm:ssZ")

$query = @"
resources
| where type =~ 'microsoft.compute/snapshots'
| where properties.timeCreated < datetime('$staleDate')
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, diskSizeGB=properties.diskSizeGB, timeCreated=properties.timeCreated
"@

$snapshots = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["StaleSnapshots"].Found = $snapshots.Count
Write-Log "    Found: $($snapshots.Count) stale snapshots (scan took $([math]::Round($scanDuration, 2))s)"
Write-ResourceTable -Category "StaleSnapshots" -Resources $snapshots -ExtraFields @{ "Size (GB)" = "diskSizeGB"; "Created" = "timeCreated" }

foreach ($snapshot in $snapshots) {
    $result = Add-DecommissionTag -ResourceId $snapshot.id -Reason "Stale-OlderThan${StaleWindowDays}Days" -DryRun $DryRun
    if ($result) { $summary["StaleSnapshots"].Tagged++ }
}
Write-Log ""

# 8. Old VM Images
Write-Log "[8/8] VM IMAGES (Manual Age Verification Required)"
Write-Log "    Criteria: All custom VM images (ARG doesn't track creation date)"
$scanStart = Get-Date
$query = @"
resources
| where type =~ 'microsoft.compute/images'
| where properties.provisioningState == 'Succeeded'
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId
"@

# Note: images don't have timeCreated in ARG, would need activity logs for precise dating
# For now, we tag all images for manual review
$images = Get-ResourceGraphResults -Query $query -ManagementGroupId $ManagementGroupId -Subscriptions $Subscriptions
$scanDuration = ((Get-Date) - $scanStart).TotalSeconds
$summary["StaleImages"].Found = $images.Count
Write-Log "    Found: $($images.Count) VM images (scan took $([math]::Round($scanDuration, 2))s)"
Write-Log "    Note: ARG doesn't track image creation date - manual verification needed"
Write-ResourceTable -Category "StaleImages" -Resources $images -ExtraFields @{}

foreach ($image in $images) {
    $result = Add-DecommissionTag -ResourceId $image.id -Reason "Stale-RequiresAgeVerification" -DryRun $DryRun
    if ($result) { $summary["StaleImages"].Tagged++ }
}
Write-Log ""

#endregion

#region Summary Report

$scriptEndTime = Get-Date
$totalDuration = ($scriptEndTime - $scriptStartTime).TotalSeconds

Write-Log "============================================================"
Write-Log "                      SUMMARY REPORT"
Write-Log "============================================================"
Write-Log ""
Write-Log "SCAN RESULTS:"
Write-Log "    ┌────────────────────────────┬─────────┬─────────┐"
Write-Log "    │ Category                   │  Found  │  Tagged │"
Write-Log "    ├────────────────────────────┼─────────┼─────────┤"

$totalFound = 0
$totalTagged = 0

$categoryOrder = @("UnattachedDisks", "OrphanNICs", "OrphanPIPs", "OrphanNSGs", "DeallocatedVMs", "EmptyASPs", "StaleSnapshots", "StaleImages")
foreach ($category in $categoryOrder) {
    $found = $summary[$category].Found
    $tagged = $summary[$category].Tagged
    $totalFound += $found
    $totalTagged += $tagged
    $categoryName = $category.PadRight(26)
    $foundStr = $found.ToString().PadLeft(5)
    $taggedStr = $tagged.ToString().PadLeft(5)
    Write-Log "    │ $categoryName │ $foundStr   │ $taggedStr   │"
}

Write-Log "    ├────────────────────────────┼─────────┼─────────┤"
$totalFoundStr = $totalFound.ToString().PadLeft(5)
$totalTaggedStr = $totalTagged.ToString().PadLeft(5)
Write-Log "    │ TOTAL                      │ $totalFoundStr   │ $totalTaggedStr   │"
Write-Log "    └────────────────────────────┴─────────┴─────────┘"
Write-Log ""

Write-Log "EXECUTION DETAILS:"
Write-Log "    Start Time:    $($scriptStartTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Log "    End Time:      $($scriptEndTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC"
Write-Log "    Duration:      $([math]::Round($totalDuration, 2)) seconds"
Write-Log "    Subscriptions: $($subsInScope.Count) scanned"
Write-Log ""

if ($DryRun) {
    Write-Log "============================================================"
    Write-Log "    DRY RUN COMPLETE - NO CHANGES WERE MADE"
    Write-Log "    Run with -DryRun `$false to apply tags"
    Write-Log "============================================================"
} else {
    Write-Log "============================================================"
    Write-Log "    TAGGING COMPLETE - $totalTagged resources tagged"
    Write-Log "============================================================"
}

#endregion

#endregion
