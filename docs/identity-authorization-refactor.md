# Identity Authorization Refactor

Status: reviewed design; execution details and ordering are governed by `identity-authorization-refactor-todo.md`

Requirement authority: current repository code and tests plus the workspace owner's 2026-09-01 authorization decisions

Module onboarding reference: `module-authorization-onboarding-sop.md` (deferred until the standalone Identity slice validates the interface model)

## 1. Outcome

Identity keeps authentication, directory, role administration, authorization policy administration, access review, audit integration, portability, and embedded/SaaS deployment. This refactor changes the functional-permission publication and enforcement model without replacing those capabilities.

The target authorization chain is:

```text
ObjectSchema / built-in surface / module surface / authored business Action
  -> canonical ActionDefinition
  -> ActionDefinition.AuthorizationStrategy + owned/referenced Permissions
  -> current PermissionDefinition rows in _identity_permissions
  -> RoleSchema.Permissions selection
  -> effective AccessBundle
  -> Action enforcement at the owning Runtime or Identity boundary
```

There is one definition source for every executable Action and one current database row for every configurable Permission. URLs are Action bindings, not permission identities. Permission usage is derived from the live Action registry and is not an authorization table.

## 2. Identity capability boundary

The following Identity capabilities remain in scope and retain their current business ownership:

| Capability | Current owner | Refactor disposition |
| --- | --- | --- |
| Password, guest, refresh, logout, password change/reset | Identity authentication | Keep |
| OIDC discovery, JWKS and access/refresh token issuance | Identity authentication | Keep |
| External providers, provider challenges, callbacks, OTP and external-account binding | Identity authentication | Keep |
| MFA, account lock/unlock, force logout and session revocation | Identity authentication/security | Keep |
| Users, departments, workforce profiles and assignments | Identity directory | Keep |
| Business-profile bindings and workforce-to-business identity projection | Identity directory | Keep |
| Operational roles, role requests and user-role assignments | Identity authorization | Keep |
| Versioned RoleSchema definitions | Identity authorization metadata | Keep; RoleSchema.Permissions remains the role configuration source |
| Permission sets, permission-set groups and deny-only guardrails | Identity authorization policy | Keep |
| Data, field, reference and export policies | Identity policy administration; Runtime enforcement for Runtime objects | Keep and separate from functional PermissionDefinition |
| Menus and role-menu assignments | Identity navigation authorization | Keep |
| Effective-access explain, reverse index, reports and access reviews | Identity governance | Keep |
| Audit binding and governance audit surfaces | Audit owner embedded by Identity | Keep |
| Embedded module and standalone SaaS deployment | Identity assembly | Keep |
| Embedded-to-SaaS portability and write fences | Identity portability | Keep and update table ownership |
| Runtime application catalog publication | Compatibility boundary | Replace, then remove |

## 3. Current problems to remove

The current implementation has five overlapping permission-definition sources:

1. `IdentityPlatformPermissionKeys` hard-codes built-in platform keys.
2. Identity HTTP routes hand-write permission gates next to route patterns.
3. Runtime synthesizes object CRUD/export Actions into `AuthorizationCatalog`.
4. Identity separately synthesizes CRUD permissions into an in-memory `PermissionDefinition` map.
5. Roles persist string permission keys inside versioned `RoleSchema` payloads.

These sources disagree today: Runtime emits create/read/update/delete/export for every object, while Identity emits only create/read/update/delete and skips `system_object`. PermissionDefinitions are replaced in memory after metadata reload and are not current database configuration. The authorization catalog also duplicates Runtime ObjectSchema fields, references and facts inside Identity.

## 4. Canonical concepts

### 4.1 ActionDefinition

An ActionDefinition is the executable authorization boundary. It has a stable key and owns:

- owner and source kind;
- method/path or non-HTTP invocation identity;
- exposure and authentication mode;
- an explicit authorization strategy: anonymous protocol, authenticated principal, self-or-permission, service identity, static all/any permissions, dynamic permission resolver, or operations identity;
- required permission references and, only when it is the canonical owner, owned PermissionDefinitions;
- risk, assurance, approval, idempotency and audit metadata;
- lifecycle status.

ActionDefinition lives with executable code or project metadata. Identity does not persist a second Action catalog. The owning process registers the Action before exposing the surface.

### 4.2 PermissionDefinition

A PermissionDefinition is a role-selectable capability key. It owns:

- stable permission key;
- resource/action labels used by configuration UI;
- one canonical definition owner;
- code-definition lifecycle (`active` or `retired`);
- administrative enablement;
- definition hash and audit timestamps.

A Permission does not own URLs, risk, approval, assurance, or a list of Action usages. Multiple Actions may require the same Permission.

### 4.3 Role and policies

RoleSchema remains the assignable responsibility definition. `RoleSchema.Permissions` stores selected functional permission keys. Data, field, reference, export, permission-set and guardrail configuration remains part of RoleSchema/authorization metadata and is not flattened into PermissionDefinition.

Operational `_identity_roles` and `_identity_user_role_assignments` remain the user assignment layer. They must not become a second functional-permission definition source.

## 5. Action sources

The complete Action registry is the union of four sources:

| Source | Examples | Permission ownership |
| --- | --- | --- |
| Object default Actions | customer create/read/update/delete/export | Object owner |
| Authored business Actions | refund.approve, order.complete | Action owner unless explicitly reusing an object permission |
| Built-in Identity/Runtime surfaces | Identity user, role, menu and security management | Owning module |
| Module-contributed surfaces | Notification, Audit and future embedded modules | Contributing module |

Every surface must register an ActionDefinition, including reviewed public/protocol surfaces. A route without a registered Action and explicit strategy is an assembly/test failure. Role-authorized Actions referencing an unknown, retired or disabled Permission fail closed; service, self and operations strategies are validated by their declared identity policy rather than by inventing a role Permission.

### 5.1 Default Object Actions

Publishing an ObjectSchema invokes one shared `DefaultActionsForObject` policy. Every successfully activated object declares a capability set; an ordinary mutable record surface emits:

- `<object>.create`
- `<object>.read`
- `<object>.update`
- `<object>.delete`
- `<object>.export`

The generator is capability-aware. It omits an operation only when the ObjectSchema explicitly declares that capability unsupported. `system_object` is not a reason to skip authorization. Internal persistence tables that are not ObjectSchema surfaces do not receive permissions.

### 5.2 Built-in Identity Actions

Identity management routes move from raw `HandleFunc(pattern, permissionWrapper(handler))` calls to registered route Actions. Management resources use read/create/update/delete plus explicit semantic commands. Existing broad `*.write` keys are compatibility inputs: a migration creates audited new RoleSchema versions that expand them to equivalent granular permissions; the broad keys are retired after no active role or permission set references them. Route registration and permission reconciliation consume the same definitions.

### 5.3 Module Actions

A module surface contribution uses the existing deployment-neutral `modulehttp.Surface`/`modulehttp.Route` contract with a lossless Action adapter (and the minimum contract extension needed for stable Action/Permission ownership). Host assembly merges it before readiness and rejects duplicate Action keys or conflicting Permission owners. The host reconciles contributed PermissionDefinitions through Identity before exposing the module surface. Standalone modules publish the same owner definitions through the service credential contract.

## 6. Database model

### 6.1 Add `_identity_permissions`

The table contains current configuration, not publication versions:

| Column | Meaning |
| --- | --- |
| `id` | stable row identity |
| `workspace_id` | workspace scope |
| `permission_key` | workspace-global permission identity |
| `resource_key` | display/grouping resource |
| `action_key` | display/grouping action |
| `label` / `description` / `category` | configuration presentation |
| `source_kind` | `platform`, `object_default`, `business_action`, `builtin_surface`, `module_surface` |
| `source_owner` | canonical owner key |
| `definition_status` | `active` or `retired`, controlled by reconciliation |
| `enabled` | administrative runtime switch, preserved by reconciliation |
| `definition_hash` | canonical source-definition hash |
| `source_snapshot_hash` | compare-and-swap hash for the owner's complete reconcile set; not a publication version |
| `created_at` / `updated_at` | audit timestamps |

Unique identity is `(workspace_id, permission_key)`. Permission keys are workspace-global because RoleSchema currently stores bare permission strings. A conflicting second canonical owner is rejected. Actions may reuse a Permission without becoming an owner.

Reconciliation updates source-controlled fields and `definition_status` but never resets an existing `enabled` decision. Missing definitions owned by the reconciled source become `retired`; they are not physically deleted while roles may still reference them. A caller that only references an existing Permission does not become its owner. `previous_snapshot_hash` compare-and-swap rejects out-of-order remote activation.

### 6.2 Add `_identity_applications`

Application authentication registration is separated from authorization metadata. The current row stores workspace/application identity, redirect URLs, status, and timestamps. Service credential secrets remain in the existing secret/config boundary; they are not copied into this table.

### 6.3 Remove catalog tables after compatibility cutover

Remove:

- `_identity_authorization_catalogs`
- `_identity_authorization_catalog_revisions`

The current Catalog endpoint remains temporarily as a compatibility adapter. During migration, catalog publication translates catalog Actions into permission reconciliation and application redirect registration. It must no longer be used as the runtime policy source. After Runtime and the SDK use the new contracts, the endpoint, store, schema ownership entries and tables are removed.

### 6.4 Tables not added

Do not add:

- `_identity_permission_usages`: usage is a live Action-registry projection;
- `_identity_permission_resources`: ObjectSchema remains the resource source;
- `_identity_role_permission_assignments`: selected keys already belong to versioned RoleSchema; a second table would create dual authority;
- permission publication/revision tables: PermissionDefinition is current reconciled configuration.

## 7. Runtime flows

### 7.1 Startup and metadata activation

```text
load metadata and built-in/module surfaces
  -> build and validate complete ActionRegistry
  -> derive owned PermissionDefinitions
  -> reconcile _identity_permissions idempotently
  -> load active/enabled PermissionDefinitions into the authorization snapshot
  -> expose listeners and report ready
```

New or changed metadata is not activated until permission reconciliation succeeds. Embedded deployment uses the host database/migration/transaction contracts. Remote deployment uses an idempotent reconciliation API and an activation receipt; it must not expose a new Action before Identity acknowledges the permission snapshot.

### 7.2 Role configuration

`GET /identity/permissions` reads current database PermissionDefinitions. Normal role authoring selects keys from active/enabled definitions and saves them in RoleSchema. Assigned retired/disabled keys remain visible with a warning so administrators can repair roles.

Saving a role or permission set rejects unknown keys. Retired or disabled keys cannot be newly selected. Unknown role references never create PermissionDefinitions. Principal construction filters unknown, retired and disabled direct/set-derived grants before guardrails. Permission state is part of the deterministic authorization-revision fingerprint, so disabling a Permission removes it from newly issued AccessBundles without rewriting every RoleSchema.

### 7.3 Request authorization

```text
request/invocation
  -> resolve registered ActionDefinition
  -> authenticate principal
  -> evaluate required Permission key(s) against current AccessBundle
  -> evaluate data/field/reference/export policy at the owning Runtime
  -> execute or deny and audit
```

The hot path does not parse catalog JSON or Permission usage rows and does not require one database query per request. AccessBundle/authorization snapshots are revisioned and cached. Unknown Action, unknown Permission or stale incompatible policy fails closed.

### 7.4 Workspace administrator

`workspace.admin` remains a reserved workspace/tenant-admin Permission. Identity issues wildcard functional authority without enumerating every catalog Action. It does not grant operations, service protocol or cross-workspace authority. Permission active/enabled checks and deny guardrails run before/over the wildcard. Runtime interprets it against its current ActionRegistry/ObjectSchema for data and field policy. Catalog-based expansion is removed.

## 8. Identity/SDK/Runtime responsibility split

| Responsibility | Identity | SDK | Runtime/owner |
| --- | --- | --- | --- |
| Authenticate subject and issue tokens | Own | Contract | Consume |
| Persist PermissionDefinition and admin enablement | Own | Reconcile/query contract | Publish owned definitions |
| Persist roles and policy configuration | Own | Contract | Configure/consume |
| Know executable URL/Action inventory | Own only Identity Actions | Action contract | Own Runtime/module Actions |
| Know Runtime objects/fields/references/facts | No mirror | Typed policy contract | Own |
| Build subject grants/policy bundle | Own | Carry and validate | Consume |
| Final Action/data/field enforcement | Identity for Identity surfaces | Shared evaluator primitives | Runtime/module owner for owned surfaces |
| Application redirect registration | Own | Registration contract | Publish application config |

`CatalogRevision` is retired. Identity exposes `AuthorizationRevision`; Runtime owns `MetadataRevision`/ActionRegistry revision. A Runtime cache key combines both when necessary.

## 9. Migration batches

### S0 — standalone Identity interface/UI validation

Before the cross-repository batches, run Identity as the authorization-management SaaS and validate one narrow vertical slice using Identity role-management and permission-management routes:

1. Define their ActionKey, capability/operation labels, Method+router template, page binding and required/owned Permission in code.
2. Persist only derived PermissionDefinitions in `_identity_permissions`; Action and URL usage remain a live registry projection.
3. Make `/identity/permissions` combine database Permission state with current Identity Action usages.
4. Update the existing Identity Admin role flow to present capability/operation/Method+URL while continuing to save versioned RoleSchema permissions.
5. Run the standalone backend and Vite admin against real APIs, then verify one allowed and one denied management request plus restart persistence.

Keep the current catalog compatibility and application registration path during S0. Do not involve Runtime, Notification, remote module reconciliation, catalog deletion, all dialects, or the full policy strategy matrix until the user accepts the UI and API shape.

### Batch A — current PermissionDefinition persistence

1. Add `_identity_permissions` to owned schema and portability.
2. Add ORM-backed permission repository and idempotent reconciliation.
3. Reconcile built-in/global plus current metadata-derived permissions during assembly.
4. Make `GET /identity/permissions` and role validation consume the persisted current catalog.
5. Preserve an in-memory immutable snapshot only as a cache of database state.

### Batch B — canonical built-in Action registry

1. Introduce deployment-neutral ActionDefinition/ActionRegistry contracts.
2. Convert Identity management routes to register Action definitions and gates together.
3. Generate Identity built-in PermissionDefinitions from the registry.
4. Add coverage tests proving every protected Identity route has exactly one Action and declared permission.
5. Remove duplicate platform-permission lists after all non-route capabilities have explicit owners.

### Batch C — application registration and compatibility projection

1. Add `_identity_applications` and move redirect validation/application existence checks to it.
2. Change Catalog Publish compatibility code to reconcile PermissionDefinitions and application registration.
3. Stop AccessBundle resolution from requiring or filtering through catalog JSON.
4. Represent administrator authority without catalog enumeration.

### Batch D — SDK and Runtime cutover

1. Add application registration and permission reconciliation contracts to the Identity SDK local and remote bindings.
2. Runtime builds one ActionRegistry from Object defaults, authored Actions, endpoint contracts and module contributions.
3. Runtime reconciles PermissionDefinitions before ready and performs final schema-aware policy validation locally.
4. Replace CatalogRevision cache semantics with authorization and metadata revisions.

### Batch E — catalog removal

1. Remove catalog SDK/HTTP APIs and Runtime catalog publisher.
2. Remove `identitycatalog` persistence and catalog policy expansion/filtering.
3. Remove catalog schemas, revisions, indexes, portability specs and tests.
4. Migrate/backfill existing application redirects and PermissionDefinitions before dropping tables.

### Batch F — administration and governance completion

1. Add current Permission enable/disable API with audit and last-admin safety.
2. Update permission UI to show active, disabled and retired states and live Action usage projection.
3. Keep role authorization changes on the normal RoleSchema configuration path; do not create a versioned Permission publication page.
4. Add governance reports for disabled/retired permissions still referenced by roles.

## 10. Acceptance contract

The refactor is complete only when all of the following hold:

1. Every Identity, Runtime and module surface, including public/protocol surfaces, resolves a registered ActionDefinition with an explicit authorization strategy.
2. Every role-authorized Action required Permission exists as an active PermissionDefinition before the surface is ready; self, service and operations Actions use their explicit non-role strategy.
3. Every exposed ObjectSchema receives exactly the supported default Action permissions.
4. Built-in Identity role-management Actions and permissions are present in the database and selectable by roles.
5. Disabling a Permission changes newly resolved access without a code deployment and survives restart/reconciliation.
6. Reconciliation is idempotent, preserves administrative enablement and retires removed source definitions.
7. Unknown, retired and disabled permissions fail closed for new grants.
8. RoleSchema remains the only source of role functional-permission selection.
9. Runtime data/field enforcement uses its current ObjectSchema without an Identity resource mirror.
10. Embedded and SaaS modes expose equivalent authorization behavior.
11. SQLite, MySQL and PostgreSQL schema and repository tests pass through `domainry-orm` rendering.
12. The database has one host-owned `_schema_migrations` ledger; the module contributes owned migration work through the host registrar.
13. Catalog tables and APIs no longer exist after the final cutover.

## 11. Explicit non-goals

- Replacing authentication, directory, workforce, role-request, access-review or audit business flows.
- Converting Permission keys into literal URLs.
- Persisting Runtime ObjectSchema or Action usage lists in Identity.
- Creating a second role-permission assignment source.
- Rewriting the existing role/version/change-plan model in the first permission-persistence batch.
