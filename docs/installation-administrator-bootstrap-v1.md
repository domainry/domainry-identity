# Installation administrator bootstrap V1

This embedded-only contract creates the first installation administrator after
the ordinary Workspace bootstrap has committed. Workspace bootstrap assigns
its initial user only the application catalog's explicitly bound
`InitialWorkspaceAdministratorRoleKey`; it never implicitly grants
`tenant_admin`.

The Runtime host enables the capability only through explicit process-start
configuration. The default is disabled. Project configuration, remote
configuration, browser requests, generated Handlers, and ordinary Workspace
administrators cannot enable or invoke it.

The host derives the initial Workspace from Runtime's durable installation
authority and sends that physical identifier only over the in-process module
boundary. Every request and receipt field is excluded from JSON. Identity
derives the single active company and fixes the role to `tenant_admin`; neither
the role nor an organization can be selected by the caller.

Within one host-owned serializable transaction, Identity creates the active
human user, assigns the fixed role, stores only the password hash, writes a
one-per-Workspace idempotency receipt, and appends the issuance audit event.
Any failure rolls back all effects. After commit, the one-time credential may
be claimed once and must be delivered through a private create-only sink. A
durable delivery acknowledgment makes later startup replays safe; a committed
but unacknowledged receipt fails closed and requires a password reset.

Contract version: `domainry-installation-administrator-bootstrap-v1`

Contract SHA-256: `30fbfdd92ae68dd93f90f5028d42a3ab8b58bb0363c2740124e4f950c73968b7`
