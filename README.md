# Entra ID PIM Baseline

Idempotent baseline script for configuring Microsoft Entra ID Privileged Identity
Management (PIM) role settings policies across client tenants. Built for repeatable
MSP deployment — companion to the [Conditional Access baseline](../Azure-Scripts) script.

## What it does

Configures PIM **role policies** (not eligible assignments) for built-in Entra ID
directory roles, grouped into tiers:

| Tier | Example Roles | Max Activation | MFA | Justification | Ticket Info | Approval |
|------|---------------|-----------------|-----|----------------|-------------|----------|
| Tier0 | Global Admin, Privileged Role Admin, Security Admin, CA Admin, Exchange Admin | 4h | ✅ | ✅ | ✅ | ✅ |
| Tier1 | User Admin, Helpdesk Admin, Intune Admin, Groups Admin | 8h | ✅ | ✅ | ❌ | ❌ |
| Default | All other mapped roles | 8h | ✅ | ✅ | ❌ | ❌ |

Tier0 also caps active (permanent) assignment duration — eligible assignments must
expire rather than persist indefinitely.

All tier definitions and role-to-tier mappings live in the `CONFIG` block at the top
of the script. Adjust per client risk appetite without touching any logic below it.

## Requirements

- PowerShell 7+
- Microsoft Graph PowerShell SDK: `Microsoft.Graph.Identity.Governance`, `Microsoft.Graph.Authentication`
- Permissions: `RoleManagementPolicy.ReadWrite.Directory`, `RoleManagement.Read.Directory`
- An approver (UPN or object ID) if any tier has `RequireApproval = $true`

```powershell
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

## Usage

**Delegated auth (interactive, single tenant):**
```powershell
.\Set-EntraPIMBaseline.ps1 -ApproverUserId "admin@client.onmicrosoft.com"
```

**App-only auth (unattended, multi-tenant runs):**
```powershell
.\Set-EntraPIMBaseline.ps1 -TenantId "client-tenant-id" -ClientId "app-id" `
    -CertificateThumbprint "ABC123..." -ApproverUserId "00000000-0000-0000-0000-000000000000"
```

**Preview only (no changes applied):**
```powershell
.\Set-EntraPIMBaseline.ps1 -ApproverUserId "admin@client.onmicrosoft.com" -WhatIf
```

## Output

Writes a timestamped CSV log (`PIM-Baseline-Log_yyyyMMdd_HHmmss.csv`) recording the
status (Success/Failed/Skipped/WhatIf) of every role processed, plus a console summary.

## Notes

- Only roles explicitly listed in `$RoleTierMap` are touched. Unmapped built-in roles
  are skipped to keep runtime reasonable — comment out the skip filter in the main
  loop if you want full tenant-wide coverage instead.
- The approval rule only sets a single-stage, single-approver flow. For multi-stage
  approval chains, extend the `Approval_EndUser_Assignment` rule body.
- Tested against built-in Entra ID directory roles only. Azure resource role PIM
  (subscription/RG scope) is a separate Graph surface and not covered here.

## License

Internal iT1 tooling — adapt freely for client engagements.
