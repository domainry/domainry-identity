# When should the host aggregate Workspace identity-account usage?

## Problems solved

- Gives installation infrastructure policy-neutral account-category counts without exposing a user directory or person-identifying data.
- Keeps Workspace selection, purpose authorization, audit evidence, paging integrity, and Application scope under the host authority.

## Business scenarios

- The platform produces one metering snapshot for each authorized active Workspace and applies its own versioned billing policy outside Identity.
- A trusted deprovisioning flow resolves one host-selected Workspace's counts before cleanup without enumerating its users.
- An operator resumes a large installation scan with an authenticated opaque cursor rather than a caller-controlled Workspace ID.

## Use when

Use this capability only from trusted installation infrastructure that has obtained the purpose-specific signed authorization receipt for `identity.workspace_identity_usage.aggregate`.

## Do not use when

Do not use it for project dashboards, user search, account export, cross-Workspace business analytics, or billing rules embedded in Identity. Project code must not select a Workspace or inspect the infrastructure receipt.

## How to use

Authorize the purpose before opening the business transaction. Submit the current V3 contract version and hash, the opaque authorization receipt, and an optional page size/cursor. The list request contains no Workspace IDs. Exact resolve accepts only a host-selected Workspace code through an infrastructure-only field. Identity returns stable account-category counts and records the authority audit; the receipt and audit identifiers are not serialized into project data.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Meter active licensed humans per Workspace | Host usage aggregation plus host billing policy | Read `active_human_accounts_with_active_role`, store a dated metering snapshot, and apply a separately versioned billing rule | Calling all-users endpoints, labeling Identity categories as billable, or counting from copied project users |
| Inspect one Workspace before deprovisioning | Infrastructure exact resolve | Let the host authority resolve the active Workspace and pass the opaque grant into the transaction-bound aggregate | Accepting a physical Workspace ID from a project Handler or treating zero accounts as proof that no other module references exist |
| Scan many Workspaces safely | Bounded keyset paging | Use page size 1–100 and replay the opaque next cursor under the same contract and authorization revision | Editing cursor contents, changing authority midway, or asking for an unbounded result |

## Example

The public request shape is intentionally small:

```json
{
  "contract_version": "domainry-identity-workspace-usage-v3",
  "contract_hash": "5f6f8a71e4a9c569628a08a1d46e41bf212e0ec4b0ba64f5a3a815bb857d5f7e",
  "page_size": 50,
  "cursor": "opaque-host-bound-cursor"
}
```

Each item contains only Workspace identity plus `active_human_accounts`, `active_human_accounts_with_active_role`, `disabled_human_accounts`, `service_accounts`, and `automation_accounts`. It never returns names, emails, Roles, credentials, or sessions. A stale contract hash, tampered cursor, inactive Workspace, wrong installation/Application/subject, or changed authorization revision is rejected.

## Permissions and scope

This is a signed installation-purpose Action, not a normal Workspace Role grant. The host authority binds installation, Application, subject, permission, authorization revision, catalog revision, and audit evidence; the serialized request cannot override them.

## Boundaries

Identity reports neutral counts only. It does not decide billing, prove that deletion is safe across other modules, expose PII, or provide a project-facing cross-Workspace query.
