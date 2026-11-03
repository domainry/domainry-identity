# Workspace Identity bootstrap V5

Identity implements one trusted bootstrap protocol:

- version: `domainry-workspace-identity-bootstrap-v5`
- hash: `09d8c1814de8b9a8b0e19c65e3bba2aeb863d6bebf89b0e2f3e2c37ee22cb13c`

The Runtime opens `BootstrapBinding`, binds its application-owned
`ProjectRoleCatalog`, and then calls `BootstrapWorkspaceIdentity` inside the
host-owned transaction. The catalog must name
`InitialWorkspaceAdministratorRoleKey` explicitly. Identity does not infer an
administrator from role names or catalog shape.

Every human role is materialized when its audience is `any`, `user`, or
`business_profile` and its assignment mode is `manual` or `request_only`. The
initial administrator role must additionally have audience `any` or `user`,
assignment mode `manual`, and no required binding. Service/system roles are not
part of Workspace bootstrap.

Identity and the SDK use the same canonical catalog digest helper. The digest
covers the complete selected authorization definitions and the explicit
administrator key. Both values enter the request fingerprint and are persisted
in the `identity.workspace_bootstrap` shared Operations result; a replay with
changed policy is an idempotency conflict.

The bootstrap graph contains the company, first store, initial human user,
selected roles, the administrator assignment at company scope, the hashed
credential, permission reconciliation, and the receipt. All DDL/DML runs
through domainry-orm and all durable writes use the host transaction. Identity
never commits or rolls it back.

The transaction-phase result is a non-secret receipt. After the host commits or
rolls back, it must call `CompleteWorkspaceIdentityBootstrap`. Only a verified
commit makes the in-memory initial credential claimable, exactly once; rollback
or expiry destroys it.

Runtime installs the shared Operations kernel before opening the bootstrap
binding. Embedded Identity binds to that owner table explicitly; standalone
Identity installs and owns the same kernel in its own database.
