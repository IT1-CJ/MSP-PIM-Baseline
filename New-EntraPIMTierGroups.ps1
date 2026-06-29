#Requires -Modules Microsoft.Graph.Groups, Microsoft.Graph.Identity.Governance, Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Creates role-assignable Entra ID groups per tier and makes them PIM-eligible
    for the roles mapped to that tier.

.DESCRIPTION
    Part 2 of the MSP PIM baseline (companion to Set-EntraPIMBaseline.ps1, which
    configures role *policy*; this script handles role *eligibility* via groups).

    For each tier in $TierGroups below, creates a role-assignable security group
    (if it doesn't already exist) and submits a PIM eligibility schedule request
    for every role listed under that tier, scoped to the directory ('/').

    This script does NOT populate group membership — that's a separate step
    (manual for beta testing now, CSV-driven in part 3 later). Techs/admins are
    added to these groups afterward, and inherit PIM eligibility for the roles
    tied to that group.

    Group names, descriptions, and role lists live in the CONFIG block below so
    they can be adjusted per client (e.g. a client with their own helpdesk team
    might rename "PIM-Tier1-Admins" to "PIM-Tier1-ClientHelpdesk" or split it
    into two groups). No other logic needs to change per client.

.PARAMETER TenantId
    Target tenant ID or domain. Required for app-only auth; optional for delegated (prompts tenant picker).

.PARAMETER ClientId
    App registration (service principal) ID for app-only auth. Omit to use delegated/interactive auth.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only auth. Required if ClientId is supplied.

.PARAMETER EligibilityDurationDays
    How long the group's PIM eligibility lasts before requiring renewal. Default 365.
    Use 0 for no expiration (permanent eligibility for the group itself — members still
    activate per the role policy from Set-EntraPIMBaseline.ps1).

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    # Delegated auth, interactive, preview only
    .\New-EntraPIMTierGroups.ps1 -WhatIf

.EXAMPLE
    # Delegated auth, apply for real
    .\New-EntraPIMTierGroups.ps1

.EXAMPLE
    # App-only auth for unattended/multi-tenant runs
    .\New-EntraPIMTierGroups.ps1 -TenantId "client-tenant-id" -ClientId "app-id" `
        -CertificateThumbprint "ABC123..."

.NOTES
    Author: CJ Johnston / iT1
    Requires scopes: Group.ReadWrite.All, RoleManagement.ReadWrite.Directory
    Version: 1.0
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter()]
    [string]$TenantId,

    [Parameter()]
    [string]$ClientId,

    [Parameter()]
    [string]$CertificateThumbprint,

    [Parameter()]
    [int]$EligibilityDurationDays = 365,

    [Parameter()]
    [string]$LogPath = ".\PIM-Group-Baseline-Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# ============================================================
# CONFIG — edit per client engagement, logic below should not need to change
# ============================================================

# One role-assignable group per tier, and the built-in directory roles it should
# be made PIM-eligible for. Keep this in sync with $RoleTierMap in
# Set-EntraPIMBaseline.ps1 so policy and eligibility line up.
$TierGroups = @{
    Tier0 = @{
        GroupName   = "PIM-Tier0-Admins"
        Description = "PIM-eligible for Tier0 (high-privilege) directory roles."
        Roles       = @(
            "Global Administrator",
            "Privileged Role Administrator",
            "Security Administrator",
            "Conditional Access Administrator",
            "Exchange Administrator",
            "SharePoint Administrator",
            "Application Administrator",
            "Cloud Application Administrator",
            "Privileged Authentication Administrator"
        )
    }
    Tier1 = @{
        GroupName   = "PIM-Tier1-Admins"
        Description = "PIM-eligible for Tier1 (delegated admin) directory roles."
        Roles       = @(
            "User Administrator",
            "Helpdesk Administrator",
            "Intune Administrator",
            "Groups Administrator",
            "Authentication Administrator",
            "License Administrator",
            "Teams Administrator"
        )
    }
}

# ============================================================
# SETUP
# ============================================================

$ErrorActionPreference = "Stop"
$results = [System.Collections.Generic.List[object]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"
    switch ($Level) {
        "ERROR" { Write-Host $line -ForegroundColor Red }
        "WARN"  { Write-Host $line -ForegroundColor Yellow }
        "OK"    { Write-Host $line -ForegroundColor Green }
        default { Write-Host $line }
    }
}

# ============================================================
# AUTH
# ============================================================

Write-Log "Connecting to Microsoft Graph..."

$requiredScopes = @("Group.ReadWrite.All", "RoleManagement.ReadWrite.Directory")

try {
    if ($ClientId -and $CertificateThumbprint -and $TenantId) {
        Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome
        Write-Log "Connected via app-only auth to tenant $TenantId" "OK"
    }
    else {
        if ($TenantId) {
            Connect-MgGraph -TenantId $TenantId -Scopes $requiredScopes -NoWelcome
        }
        else {
            Connect-MgGraph -Scopes $requiredScopes -NoWelcome
        }
        Write-Log "Connected via delegated auth" "OK"
    }
}
catch {
    Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" "ERROR"
    throw
}

$context = Get-MgContext
Write-Log "Active tenant: $($context.TenantId)"

Write-Log "Retrieving directory role definitions..."
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All

# ============================================================
# CORE FUNCTIONS
# ============================================================

function Get-OrCreateTierGroup {
    param([string]$GroupName, [string]$Description)

    $existing = Get-MgGroup -Filter "displayName eq '$GroupName'" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "  Group '$GroupName' already exists ($($existing.Id))"
        return $existing
    }

    if ($PSCmdlet.ShouldProcess($GroupName, "Create role-assignable security group")) {
        $mailNickname = ($GroupName -replace '[^a-zA-Z0-9]', '')
        $group = New-MgGroup -DisplayName $GroupName -Description $Description `
            -MailEnabled:$false -MailNickname $mailNickname -SecurityEnabled:$true `
            -IsAssignableToRole:$true -GroupTypes @()
        Write-Log "  Created group '$GroupName' ($($group.Id))" "OK"
        return $group
    }

    # WhatIf path — no group object exists yet, downstream eligibility calls are skipped.
    return $null
}

function Set-GroupRoleEligibility {
    param(
        [string]$GroupId,
        [string]$GroupName,
        [string]$RoleDisplayName,
        [string]$RoleDefinitionId,
        [int]$DurationDays
    )

    $resultRow = [ordered]@{
        Group     = $GroupName
        Role      = $RoleDisplayName
        Status    = "Pending"
        Detail    = ""
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    try {
        $existing = Get-MgRoleManagementDirectoryRoleEligibilitySchedule -Filter "principalId eq '$GroupId' and roleDefinitionId eq '$RoleDefinitionId' and directoryScopeId eq '/'" -ErrorAction SilentlyContinue

        if ($existing) {
            $resultRow.Status = "Skipped"
            $resultRow.Detail = "Eligibility already exists"
            $results.Add([pscustomobject]$resultRow)
            Write-Log "  [$GroupName -> $RoleDisplayName] Eligibility already exists — skipping"
            return
        }

        if ($PSCmdlet.ShouldProcess("$GroupName -> $RoleDisplayName", "Create PIM eligibility schedule request")) {
            $scheduleInfo = @{
                startDateTime = (Get-Date).ToUniversalTime().ToString("o")
                expiration    = if ($DurationDays -gt 0) {
                    @{ type = "AfterDuration"; duration = "P$($DurationDays)D" }
                } else {
                    @{ type = "NoExpiration" }
                }
            }

            $body = @{
                action           = "AdminAssign"
                principalId      = $GroupId
                roleDefinitionId = $RoleDefinitionId
                directoryScopeId = "/"
                scheduleInfo     = $scheduleInfo
            }

            New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $body | Out-Null

            $resultRow.Status = "Success"
            $resultRow.Detail = "Eligibility created (expires: $(if ($DurationDays -gt 0) { "$DurationDays days" } else { "never" }))"
            Write-Log "  [$GroupName -> $RoleDisplayName] Eligibility created" "OK"
        }
        else {
            $resultRow.Status = "WhatIf"
            $resultRow.Detail = "Would create eligibility"
        }
    }
    catch {
        $resultRow.Status = "Failed"
        $resultRow.Detail = $_.Exception.Message
        Write-Log "  [$GroupName -> $RoleDisplayName] FAILED: $($_.Exception.Message)" "ERROR"
    }

    $results.Add([pscustomobject]$resultRow)
}

# ============================================================
# MAIN LOOP
# ============================================================

foreach ($tierName in $TierGroups.Keys) {
    $tier = $TierGroups[$tierName]
    Write-Log "Processing $tierName -> group '$($tier.GroupName)'..."

    $group = Get-OrCreateTierGroup -GroupName $tier.GroupName -Description $tier.Description

    if (-not $group) {
        Write-Log "  Skipping role eligibility for '$($tier.GroupName)' (WhatIf — group not created)"
        foreach ($roleName in $tier.Roles) {
            $results.Add([pscustomobject][ordered]@{
                Group     = $tier.GroupName
                Role      = $roleName
                Status    = "WhatIf"
                Detail    = "Would create group, then eligibility"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            })
        }
        continue
    }

    foreach ($roleName in $tier.Roles) {
        $roleDef = $roleDefinitions | Where-Object { $_.DisplayName -eq $roleName }
        if (-not $roleDef) {
            Write-Log "  Role '$roleName' not found in tenant — skipping" "WARN"
            $results.Add([pscustomobject][ordered]@{
                Group     = $tier.GroupName
                Role      = $roleName
                Status    = "Skipped"
                Detail    = "Role not found in tenant"
                Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            })
            continue
        }

        Set-GroupRoleEligibility -GroupId $group.Id -GroupName $tier.GroupName `
            -RoleDisplayName $roleName -RoleDefinitionId $roleDef.Id -DurationDays $EligibilityDurationDays
    }
}

# ============================================================
# OUTPUT / LOGGING
# ============================================================

$results | Export-Csv -Path $LogPath -NoTypeInformation
Write-Log "Run complete. Log written to $LogPath" "OK"

$successCount = ($results | Where-Object { $_.Status -eq "Success" }).Count
$failCount    = ($results | Where-Object { $_.Status -eq "Failed" }).Count
$skipCount    = ($results | Where-Object { $_.Status -eq "Skipped" }).Count

Write-Log "Summary: $successCount succeeded, $failCount failed, $skipCount skipped"

$results | Format-Table -AutoSize

Disconnect-MgGraph | Out-Null
