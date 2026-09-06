# Workspace Identity usage aggregate

This contract is the Identity-side foundation for installation billing and
capacity policies. Identity reports current, non-sensitive account inventory;
it does not decide which accounts are billable.

## Boundary and output

The current contract is `domainry-identity-workspace-usage-v3`, with canonical
contract hash
`5f6f8a71e4a9c569628a08a1d46e41bf212e0ec4b0ba64f5a3a815bb857d5f7e`.
Both values are required so callers cannot silently consume a result whose
facts or paging-security semantics changed.

`WorkspaceIdentityUsageRequest` contains only contract version/hash, an opaque
in-process authorization receipt, page size, and protected opaque cursor. It
has no Workspace selection field. The exact
`WorkspaceIdentityUsageResolveRequest` additionally carries one canonical
Workspace code as infrastructure-only state; it is excluded from JSON and the
host resolves its physical scope inside the caller-owned transaction. A result
item contains only:

- `workspace_id`
- `active_human_accounts`
- `active_human_accounts_with_active_role`: distinct active human accounts
  having at least one active role assignment
- `disabled_human_accounts`
- `service_accounts`
- `automation_accounts`

The active-human-with-active-role fact counts one user once even when it has
multiple active role assignments. Disabled/deleted human accounts, service and
automation accounts, and assignments whose status is
revoked/suspended/expired/pending are excluded. This is an Identity fact, not
a billable label; Runtime's explicitly versioned policy decides whether to use
it for a price or invoice snapshot.

Service and automation counts each include active and disabled accounts of
that type. Deleted accounts are excluded from all inventory counts. Unknown
account types or statuses fail the page instead of being silently undercounted. Any
billable-seat decision belongs to a caller-owned, explicitly versioned billing
policy.

The implementation never reads `employee_profile` or another frontend/business
profile table. `_identity_users` is the sole account source.

## Trusted installation provider

Identity has no installation Workspace catalog in this repository. An embedded
host therefore supplies exactly one infrastructure-only provider through
`identity.DatabaseHandle.WorkspaceIdentityUsageAuthority`:

```go
type WorkspaceIdentityUsageInstallationAuthority interface {
    AuthorizeWorkspaceIdentityUsage(
        context.Context,
        WorkspaceIdentityUsageAuthorizationRequest,
    ) (WorkspaceIdentityUsageGrant, error)

    ListAuthorizedWorkspaceIdentityUsage(
        context.Context,
        WorkspaceIdentityUsageGrant,
        WorkspaceIdentityUsageCatalogQuery,
    ) (WorkspaceIdentityUsageCatalogPage, error)

    ResolveAuthorizedWorkspaceIdentityUsage(
        context.Context,
        WorkspaceIdentityUsageGrant,
        WorkspaceIdentityUsageCatalogResolve,
    ) (WorkspaceIdentityUsageCatalogEntry, error)
}
```

The authorization request always carries the Identity-owned exact installation
policy key
`identity.workspace_identity_usage.aggregate`; callers cannot choose it. The
provider returns installation, application, subject, authorization revision,
active audit Workspace, and a durable authorization audit receipt. Identity
rejects incomplete grants, wrong applications, wrong permissions, blank audit
receipts, inactive/unknown/unauthorized catalog entries, entries outside strict
bytewise Workspace ID order, duplicate entries, over-limit pages, and catalog
revision drift.

The canonical Action is a signed non-HTTP Action with that exact policy key.
It deliberately owns no Workspace database PermissionDefinition: installation
authority must not become a role grant that a Workspace administrator can
assign locally.

`AuthorizeWorkspaceIdentityUsage` is the authoritative pre-transaction audit
boundary for authorization attempts. The host must synchronously and durably
record both allow and deny decisions, and fail closed if that audit cannot be
written. The allow grant includes `AuthorizationAuditID`. Runtime obtains this
opaque receipt before starting the Action write transaction, then passes it to
the transaction-bound list or exact resolve. This ordering prevents an
independent durable audit write from contending with the Action transaction.
Identity links that receipt from a second success audit written in the host
transaction only after a safe result has been assembled. Invalid cursor,
catalog drift, exact-scope denial, and repository failure have the host
authority attempt record but no Identity success event and no result.

## Paging and persistence

The default page size is 50 and the hard maximum is 100. Identity requests
`page_size + 1` authorized active Workspaces from the provider, returns at most
`page_size`, and binds the protected keyset cursor to:

- last Workspace ID
- contract version and hash
- page size
- installation ID
- application key
- authorized subject and permission key
- authorization revision
- catalog revision

The cursor is AES-256-GCM authenticated ciphertext with a fresh nonce; a
RawURL-base64 decode reveals neither physical Workspace/installation/application
IDs nor revision values. Tampering and scope mixing fail closed before the
catalog or aggregate repositories are read. The embedding host provides a
stable 32-byte key in `DatabaseHandle.WorkspaceIdentityUsageCursorKey` and must
persist it across process restarts. Restart with the same key preserves
pagination; missing or rotated keys deliberately invalidate outstanding
cursors. This is not an HMAC-only envelope: cursor state remains confidential.

For a returned page or exact canonical resolve, persistence executes two fixed,
bounded ORM-built aggregate queries. The inventory query is equivalent to:

```sql
SELECT workspace_id, account_type, status, COUNT(*)
FROM _identity_users
WHERE workspace_id IN (...bounded authority-selected IDs...)
GROUP BY workspace_id, account_type, status
ORDER BY workspace_id, account_type, status
```

Zero-account Workspaces are merged from the bounded catalog page in memory.
The second query joins `_identity_users` to
`_identity_user_role_assignments`, filters active human users and active
assignments, de-duplicates `(workspace_id, user_id)` inside the database, then
returns only `workspace_id, COUNT(*)`. Thus a multi-role user counts once and
no user row or identifier crosses the persistence boundary.

```sql
SELECT workspace_id, COUNT(*)
FROM (
  SELECT DISTINCT u.workspace_id, u.id
  FROM _identity_users AS u
  INNER JOIN _identity_user_role_assignments AS a
    ON a.workspace_id = u.workspace_id AND a.user_id = u.id
  WHERE u.workspace_id IN (...bounded authority-selected IDs...)
    AND u.account_type = 'human'
    AND u.status = 'active'
    AND a.status = 'active'
) AS eligible_usage_user
GROUP BY workspace_id
ORDER BY workspace_id
```

There is no per-Workspace query, user-row loading, full installation scan, or
frontend fallback. The schema adds supporting
`(workspace_id, account_type, status, id)` and
`(workspace_id, status, user_id)` indexes through Identity's source-owned
migration submitted to the host's sole `_schema_migrations` ledger.

## Embedded binding and current-read semantics

The module exposes only `EmbeddedWorkspaceIdentityUsageBinding`, whose binder
requires a real host-owned transaction. It rejects pools and bare connections,
and returns only the narrow aggregate capability; handlers never receive the
transaction or database handle.

This is a current usage read, not an idempotent command. Results and successful
audits are intentionally not replay-cached. Repeating the request, including
after process restart, re-authorizes, re-reads current grouped counts, and
writes a new success audit. The exact path accepts no physical Workspace ID or
ID list, and the host selects exactly one active Workspace from its canonical
code. The caller retains commit/rollback ownership so the exact usage fact can
commit or roll back with the business mutation that consumes it.
