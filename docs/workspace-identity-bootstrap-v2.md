# Workspace Identity bootstrap V2

Workspace is the only isolation boundary. This contract has no Tenant entity,
Tenant identifier, Tenant registry, or Tenant-to-Workspace mapping. The string
`tenant_admin` is retained only as one required role key; its V2 display label
is **Platform administrator** and it does not imply a separate entity.

## Pinned contract

- Version: `domainry-workspace-identity-bootstrap-v2`
- SHA-256: `5011287354029d67c64e1f9dedf3767234c9af8d7ec7e29886a9b4b419ccc9c8`
- Canonical contract string:
  `domainry-workspace-identity-bootstrap-v2|request:invocation_id,workspace_id,company_id,company_code,company_name,first_store_id,first_store_code,first_store_name,initial_admin_user_id,initial_admin_login_id,initial_admin_name|roles:tenant_admin,headquarters_admin,store_manager,staff|assignment:initial_admin=headquarters_admin@company|result:receipt_only|completion:committed,rolled_back|credential:post_commit_one_time_nonpersistent`

The SDK request and completion structs are deliberately excluded from JSON.
No HTTP route exposes this capability, so browser input cannot choose a role,
organization parent, `owner_org_id`, Workspace selector, or graph identifier.

## Fixed graph

The trusted host supplies stable identifiers and human-readable company/store
codes and names. Identity derives and atomically persists this graph inside the
host transaction:

```text
Workspace
└── company Organization (active, root)
    ├── first store OrganizationUnit (active, node_type=store)
    └── initial human administrator (active, org_id=company)
        └── headquarters_admin (active, sole initial assignment)
```

Exactly these four active materialized roles are created:
`tenant_admin`, `headquarters_admin`, `store_manager`, and `staff`. The initial
administrator receives only `headquarters_admin`. V2 never synthesizes an
`admin` role and never assigns the installation-level `tenant_admin` role.
All four keys must be present in the application-owned bootstrap role catalog;
a missing key fails before durable graph writes.

Identity owns only the organization/user/role/credential graph. Store business
configuration remains host-owned and can be written later in the same outer
unit of work before the host commits.

## Transaction and one-time credential protocol

1. The host opens `BootstrapBinding`, binds its project role catalog, and begins
   its outer database transaction.
2. It calls `BootstrapWorkspaceIdentityV2`. Identity joins that transaction and
   returns only a non-secret receipt.
3. The host writes its own business state in the same unit of work, then commits
   or rolls back.
4. The host must call `CompleteWorkspaceIdentityBootstrapV2` with `committed` or
   `rolled_back`. A rollback immediately zeros and removes the volatile secret.
   A commit is accepted only when the receipt is visible outside the transaction.
5. After a verified commit, the host calls
   `ClaimWorkspaceIdentityBootstrapCredentialV2` once. The plaintext is removed
   and zeroed as it is returned. A second claim fails closed.

Plaintext is never written to a credential row, receipt, replay response, or
audit payload. Pending plaintext lives only in process memory, expires after
five minutes, and is destroyed on rollback, replacement, claim, or binding
close. A crash before claim intentionally makes the credential unrecoverable;
the persisted password hash cannot reconstruct it.

The same invocation and same graph replays the non-secret receipt without
creating duplicates. Reusing an invocation for a different graph, starting a
second invocation for the Workspace, or encountering preexisting Workspace
Identity state fails closed. Any returned error requires the host to roll back,
leaving zero committed Identity bootstrap effects.

Protocol V3's `BootstrapBinding` exposes only V2. The role-selectable V1
`WorkspaceProvisioner` remains a separately named legacy interface for older
ordinary in-process integrations and is not reachable from the V3 bootstrap
factory result.

