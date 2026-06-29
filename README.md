# Entra ID PIM Baseline

Idempotent baseline scripts for rolling out Microsoft Entra ID Privileged Identity
Management (PIM) across client tenants. Built for repeatable MSP deployment —
companion to the [Conditional Access baseline](../Azure-Scripts) script.

Two parts, run in order:

1. **[Set-EntraPIMBaseline.ps1](#part-1--role-policy)** — configures PIM **role policy**
   (activation duration, MFA, approval, etc.) for built-in directory roles.
2. **[New-EntraPIMTierGroups.ps1](#part-2--tier-groups--eligibility)** — creates
   role-assignable **tier groups** and makes them PIM-**eligible** for the roles
   in that tier.

A planned part 3 will populate group membership from a CSV (deferred until past
beta testing — for now, add members manually in the Entra portal or via
`Add-MgGroupMember` to test).

## Part 1 — Role Policy

`Set-EntraPIMBaseline.ps1`

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
- Microsoft Graph PowerShell SDK: `Microsoft.Graph.Identity.Governance`, `Microsoft.Graph.Authentication`, `Microsoft.Graph.Users`, `Microsoft.Graph.Identity.SignIns`
- Permissions: `RoleManagementPolicy.ReadWrite.Directory`, `RoleManagement.Read.Directory`, `User.Read.All` (to resolve `-ApproverUserId` by UPN)
- An approver (UPN or object ID) if any tier has `RequireApproval = $true`

```powershell
Install-Module Microsoft.Graph.Identity.Governance -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Microsoft.Graph.Users -Scope CurrentUser
Install-Module Microsoft.Graph.Identity.SignIns -Scope CurrentUser
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

### Part 1 Notes

- Only roles explicitly listed in `$RoleTierMap` are touched. Unmapped built-in roles
  are skipped to keep runtime reasonable — comment out the skip filter in the main
  loop if you want full tenant-wide coverage instead.
- The approval rule only sets a single-stage, single-approver flow. For multi-stage
  approval chains, extend the `Approval_EndUser_Assignment` rule body.
- Tested against built-in Entra ID directory roles only. Azure resource role PIM
  (subscription/RG scope) is a separate Graph surface and not covered here.

## Part 2 — Tier Groups & Eligibility

`New-EntraPIMTierGroups.ps1`

Creates one **role-assignable security group** per tier and submits a PIM
**eligibility schedule request** for every role mapped to that tier in the
`$TierGroups` CONFIG block. Idempotent — rerunning skips groups/eligibility
that already exist.

This does **not** create or modify roles, and does **not** add any members.
It only creates the group "container" and grants it eligibility to activate
the tier's roles — members still go through normal PIM activation (subject to
whatever policy Part 1 configured).

`$TierGroups` mirrors `$RoleTierMap` from Part 1 by default. Rename groups or
split tiers per client as needed — e.g. a client with their own in-house
helpdesk might rename `PIM-Tier1-Admins` to `PIM-Tier1-ClientHelpdesk`, or add
a third group for a client-specific role subset. Keep the role lists in sync
with Part 1's tiers so policy and eligibility line up.

### Part 2 Requirements

- Microsoft Graph PowerShell SDK: `Microsoft.Graph.Groups`, `Microsoft.Graph.Identity.Governance`, `Microsoft.Graph.Authentication`
- Permissions: `Group.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`

```powershell
Install-Module Microsoft.Graph.Groups -Scope CurrentUser
```

### Part 2 Usage

**Preview only:**
```powershell
.\New-EntraPIMTierGroups.ps1 -WhatIf
```

**Apply for real:**
```powershell
.\New-EntraPIMTierGroups.ps1
```

**App-only auth:**
```powershell
.\New-EntraPIMTierGroups.ps1 -TenantId "client-tenant-id" -ClientId "app-id" -CertificateThumbprint "ABC123..."
```

**Custom eligibility duration (default 365 days, 0 = no expiration):**
```powershell
.\New-EntraPIMTierGroups.ps1 -EligibilityDurationDays 180
```

### Part 2 Notes

- Groups are created with `IsAssignableToRole = $true`, which Entra only allows
  at creation time — you cannot retrofit this onto an existing group.
- Adding members for beta testing: `Add-MgGroupMember -GroupId <id> -DirectoryObjectId <userId>`,
  or via the Entra portal (Groups → the tier group → Members).
- Writes a timestamped CSV log (`PIM-Group-Baseline-Log_yyyyMMdd_HHmmss.csv`).

## License

Internal iT1 tooling — adapt freely for client engagements.
