#Requires -Modules Microsoft.Graph.Identity.Governance, Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Deploys a baseline Entra ID PIM role policy configuration across tiered admin roles.

.DESCRIPTION
    Configures Microsoft Entra ID Privileged Identity Management (PIM) role settings policies
    for built-in directory roles, grouped into tiers (Tier0 / Tier1 / Default). Each tier defines
    activation duration, MFA requirement, approval requirement + approvers, justification
    requirement, and ticket info requirement.

    Designed for MSP reuse across client tenants — all role-to-tier mapping and policy values
    live in the CONFIG block below. No other logic needs to change per client.

.PARAMETER TenantId
    Target tenant ID or domain. Required for app-only auth; optional for delegated (prompts tenant picker).

.PARAMETER ClientId
    App registration (service principal) ID for app-only auth. Omit to use delegated/interactive auth.

.PARAMETER CertificateThumbprint
    Certificate thumbprint for app-only auth. Required if ClientId is supplied.

.PARAMETER ApproverUserId
    Object ID (or UPN) of the user to set as approver for Tier0 roles requiring approval.
    Required if any Tier0 role has RequireApproval = $true.

.PARAMETER WhatIf
    Preview changes without applying them.

.EXAMPLE
    # Delegated auth, interactive
    .\Set-EntraPIMBaseline.ps1 -ApproverUserId "admin@client.onmicrosoft.com"

.EXAMPLE
    # App-only auth for unattended/multi-tenant runs
    .\Set-EntraPIMBaseline.ps1 -TenantId "client-tenant-id" -ClientId "app-id" `
        -CertificateThumbprint "ABC123..." -ApproverUserId "00000000-0000-0000-0000-000000000000"

.EXAMPLE
    # Preview only
    .\Set-EntraPIMBaseline.ps1 -ApproverUserId "admin@client.onmicrosoft.com" -WhatIf

.NOTES
    Author: CJ Johnston / iT1
    Requires scopes: RoleManagementPolicy.ReadWrite.Directory, RoleManagement.Read.Directory
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
    [string]$ApproverUserId,

    [Parameter()]
    [string]$LogPath = ".\PIM-Baseline-Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# ============================================================
# CONFIG — edit per client engagement, logic below should not need to change
# ============================================================

# Tier definitions: activation behavior per tier
$TierPolicies = @{
    Tier0 = @{
        MaxActivationHours      = 4
        RequireMFA              = $true
        RequireJustification    = $true
        RequireTicketInfo       = $true
        RequireApproval         = $true
        ActiveAssignmentMaxDays = 0    # 0 = require expiration (no permanent active assignment)
    }
    Tier1 = @{
        MaxActivationHours      = 8
        RequireMFA              = $true
        RequireJustification    = $true
        RequireTicketInfo       = $false
        RequireApproval         = $false
        ActiveAssignmentMaxDays = 180
    }
    Default = @{
        MaxActivationHours      = 8
        RequireMFA              = $true
        RequireJustification    = $true
        RequireTicketInfo       = $false
        RequireApproval         = $false
        ActiveAssignmentMaxDays = 180
    }
}

# Built-in role display names mapped to tiers. Anything not listed falls back to "Default".
# Adjust this list per client risk appetite — these are sane MSP-baseline starting points.
$RoleTierMap = @{
    "Global Administrator"              = "Tier0"
    "Privileged Role Administrator"     = "Tier0"
    "Security Administrator"            = "Tier0"
    "Conditional Access Administrator"  = "Tier0"
    "Exchange Administrator"            = "Tier0"
    "SharePoint Administrator"          = "Tier0"
    "Application Administrator"         = "Tier0"
    "Cloud Application Administrator"   = "Tier0"
    "Privileged Authentication Administrator" = "Tier0"

    "User Administrator"                = "Tier1"
    "Helpdesk Administrator"            = "Tier1"
    "Intune Administrator"              = "Tier1"
    "Groups Administrator"              = "Tier1"
    "Authentication Administrator"      = "Tier1"
    "License Administrator"             = "Tier1"
    "Teams Administrator"               = "Tier1"
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

# Validate approver is supplied if any Tier0-equivalent policy requires approval
$anyApprovalRequired = $TierPolicies.Values | Where-Object { $_.RequireApproval } | Select-Object -First 1
if ($anyApprovalRequired -and -not $ApproverUserId) {
    Write-Log "At least one tier requires approval but -ApproverUserId was not supplied." "ERROR"
    throw "ApproverUserId is required when RequireApproval is true for any tier."
}

# ============================================================
# AUTH
# ============================================================

Write-Log "Connecting to Microsoft Graph..."

$requiredScopes = @("RoleManagementPolicy.ReadWrite.Directory", "RoleManagement.Read.Directory", "User.Read.All")

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

# Resolve approver to an object ID if a UPN was supplied
$resolvedApproverId = $null
if ($ApproverUserId) {
    if ($ApproverUserId -match '^[0-9a-fA-F-]{36}$') {
        $resolvedApproverId = $ApproverUserId
    }
    else {
        try {
            $approverUser = Get-MgUser -UserId $ApproverUserId -ErrorAction Stop
            $resolvedApproverId = $approverUser.Id
            Write-Log "Resolved approver '$ApproverUserId' to object ID $resolvedApproverId"
        }
        catch {
            Write-Log "Could not resolve ApproverUserId '$ApproverUserId': $($_.Exception.Message)" "ERROR"
            throw
        }
    }
}

# ============================================================
# GET ROLE DEFINITIONS
# ============================================================

Write-Log "Retrieving directory role definitions..."
$roleDefinitions = Get-MgRoleManagementDirectoryRoleDefinition -All

# ============================================================
# CORE FUNCTION — apply policy to a single role
# ============================================================

function Set-RolePolicyForRole {
    param(
        [string]$RoleDisplayName,
        [string]$RoleDefinitionId,
        [string]$TierName,
        [hashtable]$Policy
    )

    $resultRow = [ordered]@{
        Role       = $RoleDisplayName
        Tier       = $TierName
        Status     = "Pending"
        Detail     = ""
        Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }

    try {
        # Find the policy assignment for this role definition
        $policyAssignment = Get-MgPolicyRoleManagementPolicyAssignment -Filter "scopeId eq '/' and scopeType eq 'Directory' and roleDefinitionId eq '$RoleDefinitionId'"

        if (-not $policyAssignment) {
            $resultRow.Status = "Skipped"
            $resultRow.Detail = "No policy assignment found for role"
            $results.Add([pscustomobject]$resultRow)
            Write-Log "  [$RoleDisplayName] No policy assignment found — skipping" "WARN"
            return
        }

        $policyId = $policyAssignment.PolicyId

        # Get current policy rules
        $policyRules = Get-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId

        if ($PSCmdlet.ShouldProcess($RoleDisplayName, "Update PIM role policy ($TierName baseline)")) {

            # --- Rule: Expiration_EndUser_Assignment (max activation duration) ---
            $expirationRule = $policyRules | Where-Object { $_.Id -eq "Expiration_EndUser_Assignment" }
            if ($expirationRule) {
                $body = @{
                    "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                    id            = "Expiration_EndUser_Assignment"
                    isExpirationRequired = $true
                    maximumDuration = "PT$($Policy.MaxActivationHours)H"
                }
                Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId `
                    -UnifiedRoleManagementPolicyRuleId "Expiration_EndUser_Assignment" -BodyParameter $body
            }

            # --- Rule: Enablement_EndUser_Assignment (MFA + justification on activation) ---
            $enablementRule = $policyRules | Where-Object { $_.Id -eq "Enablement_EndUser_Assignment" }
            if ($enablementRule) {
                $enabledRules = @()
                if ($Policy.RequireMFA) { $enabledRules += "MultiFactorAuthentication" }
                if ($Policy.RequireJustification) { $enabledRules += "Justification" }
                if ($Policy.RequireTicketInfo) { $enabledRules += "Ticketing" }

                $body = @{
                    "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
                    id            = "Enablement_EndUser_Assignment"
                    enabledRules  = $enabledRules
                }
                Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId `
                    -UnifiedRoleManagementPolicyRuleId "Enablement_EndUser_Assignment" -BodyParameter $body
            }

            # --- Rule: Approval_EndUser_Assignment (approval required + approvers) ---
            $approvalRule = $policyRules | Where-Object { $_.Id -eq "Approval_EndUser_Assignment" }
            if ($approvalRule) {
                $approvalBody = @{
                    "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyApprovalRule"
                    id            = "Approval_EndUser_Assignment"
                    setting       = @{
                        "@odata.type"      = "#microsoft.graph.approvalSettings"
                        isApprovalRequired = $Policy.RequireApproval
                        approvalStages     = @()
                    }
                }

                if ($Policy.RequireApproval -and $resolvedApproverId) {
                    $approvalBody.setting.approvalStages = @(
                        @{
                            "@odata.type"               = "#microsoft.graph.unifiedApprovalStage"
                            approvalStageTimeOutInDays  = 1
                            isApproverJustificationRequired = $true
                            escalationTimeInMinutes     = 0
                            primaryApprovers            = @(
                                @{
                                    "@odata.type" = "#microsoft.graph.singleUser"
                                    userId        = $resolvedApproverId
                                }
                            )
                        }
                    )
                }

                Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId `
                    -UnifiedRoleManagementPolicyRuleId "Approval_EndUser_Assignment" -BodyParameter $approvalBody
            }

            # --- Rule: Expiration_Admin_Eligibility (active assignment max duration) ---
            if ($Policy.ContainsKey("ActiveAssignmentMaxDays")) {
                $activeExpirationRule = $policyRules | Where-Object { $_.Id -eq "Expiration_Admin_Assignment" }
                if ($activeExpirationRule) {
                    if ($Policy.ActiveAssignmentMaxDays -gt 0) {
                        $body = @{
                            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                            id            = "Expiration_Admin_Assignment"
                            isExpirationRequired = $true
                            maximumDuration = "P$($Policy.ActiveAssignmentMaxDays)D"
                        }
                    }
                    else {
                        $body = @{
                            "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                            id            = "Expiration_Admin_Assignment"
                            isExpirationRequired = $false
                        }
                    }
                    Update-MgPolicyRoleManagementPolicyRule -UnifiedRoleManagementPolicyId $policyId `
                        -UnifiedRoleManagementPolicyRuleId "Expiration_Admin_Assignment" -BodyParameter $body
                }
            }

            $resultRow.Status = "Success"
            $resultRow.Detail = "Applied $TierName baseline"
            Write-Log "  [$RoleDisplayName] Applied $TierName baseline" "OK"
        }
        else {
            $resultRow.Status = "WhatIf"
            $resultRow.Detail = "Would apply $TierName baseline"
        }
    }
    catch {
        $resultRow.Status = "Failed"
        $resultRow.Detail = $_.Exception.Message
        Write-Log "  [$RoleDisplayName] FAILED: $($_.Exception.Message)" "ERROR"
    }

    $results.Add([pscustomobject]$resultRow)
}

# ============================================================
# MAIN LOOP
# ============================================================

Write-Log "Applying PIM baseline across $($roleDefinitions.Count) directory roles..."

foreach ($role in $roleDefinitions) {

    $tierName = if ($RoleTierMap.ContainsKey($role.DisplayName)) {
        $RoleTierMap[$role.DisplayName]
    }
    else {
        "Default"
    }

    # Skip applying "Default" tier to every single built-in role to keep runtime reasonable —
    # comment out this filter if you want full tenant-wide coverage instead of just mapped roles.
    if ($tierName -eq "Default" -and -not $RoleTierMap.ContainsKey($role.DisplayName)) {
        continue
    }

    $policy = $TierPolicies[$tierName]
    Set-RolePolicyForRole -RoleDisplayName $role.DisplayName -RoleDefinitionId $role.Id -TierName $tierName -Policy $policy
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
