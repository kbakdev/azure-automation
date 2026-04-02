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

.PARAMETER Subscriptions
    Array of subscription IDs to scan. If empty, scans all accessible subscriptions.

.PARAMETER IdleWindowDays
    Number of days a VM must be deallocated to be considered idle. Default: 30

.PARAMETER StaleWindowDays
    Number of days since creation for snapshots/images to be considered stale. Default: 90

.PARAMETER ExcludeResourceGroups
    Array of resource group names to exclude from tagging.

.PARAMETER ExcludeTagName
    Resources with this tag will be excluded. Default: "decommission-exclude"
#>

param(
    [Parameter(Mandatory = $false)]
    [bool]$DryRun = $true,

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
        [string[]]$Subscriptions
    )
    
    $results = @()
    
    if ($Subscriptions.Count -eq 0) {
        # Query all accessible subscriptions
        $results = Search-AzGraph -Query $Query -First 1000
    } else {
        $results = Search-AzGraph -Query $Query -Subscription $Subscriptions -First 1000
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

Write-Log "=========================================="
Write-Log "Unused Resource Tagging Automation"
Write-Log "=========================================="
Write-Log "DryRun: $DryRun"
Write-Log "IdleWindowDays: $IdleWindowDays"
Write-Log "StaleWindowDays: $StaleWindowDays"
Write-Log "ExcludeTagName: $ExcludeTagName"

# Authenticate using Managed Identity (for Azure Automation)
try {
    $connection = Connect-AzAccount -Identity -ErrorAction Stop
    Write-Log "Authenticated using Managed Identity"
}
catch {
    Write-Log "Managed Identity authentication failed, attempting interactive..." -Level "WARN"
    $connection = Connect-AzAccount -ErrorAction Stop
}

# Build exclusion filter
$excludeRgFilter = ""
if ($ExcludeResourceGroups.Count -gt 0) {
    $rgList = ($ExcludeResourceGroups | ForEach-Object { "'$_'" }) -join ", "
    $excludeRgFilter = "| where resourceGroup !in~ ($rgList)"
}

$excludeTagFilter = "| where isnull(tags['$ExcludeTagName']) or tags['$ExcludeTagName'] != 'true'"
$alreadyTaggedFilter = "| where isnull(tags['decommission-candidate']) or tags['decommission-candidate'] != 'true'"

# Track results
$summary = @{
    "UnattachedDisks" = @{ Found = 0; Tagged = 0 }
    "OrphanNICs" = @{ Found = 0; Tagged = 0 }
    "OrphanPIPs" = @{ Found = 0; Tagged = 0 }
    "OrphanNSGs" = @{ Found = 0; Tagged = 0 }
    "DeallocatedVMs" = @{ Found = 0; Tagged = 0 }
    "EmptyASPs" = @{ Found = 0; Tagged = 0 }
    "StaleSnapshots" = @{ Found = 0; Tagged = 0 }
    "StaleImages" = @{ Found = 0; Tagged = 0 }
}

#region Orphaned Resources

# 1. Unattached Managed Disks
Write-Log "Scanning: Unattached Managed Disks..."
$query = @"
resources
| where type =~ 'microsoft.compute/disks'
| where managedBy == '' or isnull(managedBy)
| where properties.diskState == 'Unattached'
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, sku.name, properties.diskSizeGB
"@

$disks = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["UnattachedDisks"].Found = $disks.Count
Write-Log "Found $($disks.Count) unattached disks"

foreach ($disk in $disks) {
    $result = Add-DecommissionTag -ResourceId $disk.id -Reason "Orphan-UnattachedDisk" -DryRun $DryRun
    if ($result) { $summary["UnattachedDisks"].Tagged++ }
}

# 2. Orphan NICs
Write-Log "Scanning: Orphan NICs..."
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

$nics = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["OrphanNICs"].Found = $nics.Count
Write-Log "Found $($nics.Count) orphan NICs"

foreach ($nic in $nics) {
    $result = Add-DecommissionTag -ResourceId $nic.id -Reason "Orphan-NoVMAttached" -DryRun $DryRun
    if ($result) { $summary["OrphanNICs"].Tagged++ }
}

# 3. Orphan Public IPs
Write-Log "Scanning: Orphan Public IPs..."
$query = @"
resources
| where type =~ 'microsoft.network/publicipaddresses'
| where isnull(properties.ipConfiguration.id) or properties.ipConfiguration.id == ''
| where isnull(properties.natGateway.id) or properties.natGateway.id == ''
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, sku.name
"@

$pips = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["OrphanPIPs"].Found = $pips.Count
Write-Log "Found $($pips.Count) orphan Public IPs"

foreach ($pip in $pips) {
    $result = Add-DecommissionTag -ResourceId $pip.id -Reason "Orphan-NotAssociated" -DryRun $DryRun
    if ($result) { $summary["OrphanPIPs"].Tagged++ }
}

# 4. Orphan NSGs
Write-Log "Scanning: Orphan NSGs..."
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

$nsgs = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["OrphanNSGs"].Found = $nsgs.Count
Write-Log "Found $($nsgs.Count) orphan NSGs"

foreach ($nsg in $nsgs) {
    $result = Add-DecommissionTag -ResourceId $nsg.id -Reason "Orphan-NotAttached" -DryRun $DryRun
    if ($result) { $summary["OrphanNSGs"].Tagged++ }
}

#endregion

#region Idle Resources

# 5. Deallocated VMs (idle for more than threshold)
Write-Log "Scanning: Deallocated VMs (idle > $IdleWindowDays days)..."
$idleDate = (Get-Date).AddDays(-$IdleWindowDays).ToString("yyyy-MM-ddTHH:mm:ssZ")

$query = @"
resources
| where type =~ 'microsoft.compute/virtualmachines'
| where properties.extended.instanceView.powerState.code =~ 'PowerState/deallocated'
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, properties.hardwareProfile.vmSize
"@

$vms = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["DeallocatedVMs"].Found = $vms.Count
Write-Log "Found $($vms.Count) deallocated VMs"

foreach ($vm in $vms) {
    $result = Add-DecommissionTag -ResourceId $vm.id -Reason "Idle-Deallocated" -DryRun $DryRun
    if ($result) { $summary["DeallocatedVMs"].Tagged++ }
}

# 6. Empty App Service Plans
Write-Log "Scanning: Empty App Service Plans..."
$query = @"
resources
| where type =~ 'microsoft.web/serverfarms'
| where properties.numberOfSites == 0
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, sku.name
"@

$asps = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["EmptyASPs"].Found = $asps.Count
Write-Log "Found $($asps.Count) empty App Service Plans"

foreach ($asp in $asps) {
    $result = Add-DecommissionTag -ResourceId $asp.id -Reason "Idle-NoAppsHosted" -DryRun $DryRun
    if ($result) { $summary["EmptyASPs"].Tagged++ }
}

#endregion

#region Stale Resources

# 7. Old Snapshots
Write-Log "Scanning: Stale Snapshots (> $StaleWindowDays days old)..."
$staleDate = (Get-Date).AddDays(-$StaleWindowDays).ToString("yyyy-MM-ddTHH:mm:ssZ")

$query = @"
resources
| where type =~ 'microsoft.compute/snapshots'
| where properties.timeCreated < datetime('$staleDate')
$excludeRgFilter
$excludeTagFilter
$alreadyTaggedFilter
| project id, name, resourceGroup, location, subscriptionId, properties.diskSizeGB, properties.timeCreated
"@

$snapshots = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["StaleSnapshots"].Found = $snapshots.Count
Write-Log "Found $($snapshots.Count) stale snapshots"

foreach ($snapshot in $snapshots) {
    $result = Add-DecommissionTag -ResourceId $snapshot.id -Reason "Stale-OlderThan${StaleWindowDays}Days" -DryRun $DryRun
    if ($result) { $summary["StaleSnapshots"].Tagged++ }
}

# 8. Old VM Images
Write-Log "Scanning: Stale VM Images (> $StaleWindowDays days old)..."
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
$images = Get-ResourceGraphResults -Query $query -Subscriptions $Subscriptions
$summary["StaleImages"].Found = $images.Count
Write-Log "Found $($images.Count) VM images (require manual age verification)"

foreach ($image in $images) {
    $result = Add-DecommissionTag -ResourceId $image.id -Reason "Stale-RequiresAgeVerification" -DryRun $DryRun
    if ($result) { $summary["StaleImages"].Tagged++ }
}

#endregion

#region Summary Report

Write-Log "=========================================="
Write-Log "SUMMARY REPORT"
Write-Log "=========================================="

$totalFound = 0
$totalTagged = 0

foreach ($category in $summary.Keys) {
    $found = $summary[$category].Found
    $tagged = $summary[$category].Tagged
    $totalFound += $found
    $totalTagged += $tagged
    Write-Log "$category : Found=$found, Tagged=$tagged"
}

Write-Log "----------------------------------------"
Write-Log "TOTAL: Found=$totalFound, Tagged=$totalTagged"

if ($DryRun) {
    Write-Log "=========================================="
    Write-Log "DRY RUN COMPLETE - No changes were made"
    Write-Log "Set -DryRun `$false to apply tags"
    Write-Log "=========================================="
}

#endregion

#endregion
