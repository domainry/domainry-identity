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
  -> ActionDefinition.AuthorizationStrategy + same-key Permission when role-authorized
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
| Users, personnel facts, direct-manager/reporting paths, and organization units | Identity directory | Keep |
| Business-profile bindings and user-to-business identity projection | Identity directory | Keep |
| Operational roles, role requests and user-role assignments | Identity authorization | Keep |
| Versioned RoleSchema definitions | Identity authorization metadata | Keep; RoleSchema.Permissions remains the role configuration source |
| Permission sets and permission-set groups | Identity data/governance policy | Keep only for non-functional policy composition; they do not grant Action Permissions |
| Data, field, reference and export policies | Identity policy administration; Runtime enforcement for Runtime objects | Keep and separate from functional PermissionDefinition |
| Menus and role-menu assignments | Identity navigation authorization | Keep |
| Effective-access explain, reverse index, reports and access reviews | Identity governance | Keep |
| Audit binding and governance audit surfaces | Audit owner embedded by Identity | Keep |
| Embedded module and standalone SaaS deployment | Identity assembly | Keep |
| Embedded-to-SaaS portability and write fences | Identity portability | Keep and update table ownership |
| Runtime application catalog publication | Obsolete boundary | Remove directly; the code has not shipped and no compatibility adapter is permitted |

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
- an explicit authorization strategy: anonymous protocol, authenticated principal, self action, delegated credential, service identity, exact role permission, or operations identity;
- exactly one same-key owned PermissionDefinition when the Action is role-authorized; exceptional non-role strategies own no role Permission;
- risk, assurance, approval, idempotency and audit metadata;
- lifecycle status.

ActionDefinition lives with executable code or project metadata. Identity does not persist a second Action catalog. The owning process registers the Action before exposing the surface.

### 4.2 PermissionDefinition

A PermissionDefinition is a role-selectable capability key. It owns:

- stable permission key;
- resource/operation labels used by configuration UI;
- one canonical definition owner;
- code-definition lifecycle (`active` or `retired`);
- administrative enablement;
- definition hash and audit timestamps.

A Permission does not own URLs, risk, approval, assurance, or a list of Action usages. A role-authorized Action and its Permission use the same stable key; Permission reuse, all/any lists, aliases, and dynamic permission callbacks are not part of the model.

### 4.3 Role and policies

RoleSchema remains the assignable responsibility definition. `RoleSchema.Permissions[]` is the only functional Action-grant authority. Each entry binds one exact `permission_key` to its own `data_scope`; field, reference, export, permission-set and guardrail configuration remains separate policy metadata and cannot add functional Action grants.

Operational `_identity_roles` and `_identity_user_role_assignments` remain the user assignment layer. They must not become a second functional-permission definition source.

### 4.4 Data scope and support organization

There is no role-level `DataPermission`. Each exact Action grant carries one canonical `data_scope` and optional denial-audit intent. Read, create, update, delete, export, and business commands are independent entries, so the same resource may deliberately use different scopes for different Actions. Custom predicates exist only in the compiled SDK `AccessBundle`, never in role authoring.

The Identity SDK evaluator currently exposes separate query and mutation filter channels. That is an execution-protocol detail, not role configuration: the Identity SDK adapter compiles the same canonical data scope into both channels, while the evaluator still requires the exact Action FunctionGrant before either channel can be used. For example, `customer.read` plus `target_org` can query matching customers, but it cannot execute `customer.update` even when the resource facts match.

`IdentityUser.OrgID` remains the user's real primary organization. A support worker who needs an additional customer-service view uses the separate optional `support_org_id`; assigning it never changes the worker's primary organization. Identity validates that the support root is active and derives its active organization subtree into the trusted `support_org_scope_ids` subject fact. Missing, disabled, or empty support scope resolves to an empty set and fails closed.

The role uses the canonical `target_org` scope. The application-owned customer role declares the scope on each exact Action grant:

```json
{
  "permissions": [
    {
      "permission_key": "customer.read",
      "data_scope": "target_org"
    }
  ]
}
```

The customer application still owns `customer`, `owner_org_id`, and the exact Action definitions. Identity owns only the user assignment, organization graph, trusted derived claim, and policy bundle compilation.

## 5. Action sources

The complete Action registry is the union of four sources:

| Source | Examples | Permission ownership |
| --- | --- | --- |
| Object default Actions | customer create/read/update/delete/export | Object owner |
| Authored business Actions | refund.approve, order.complete | Action owner; the same-key Permission is owned with the Action |
| Built-in Identity/Runtime surfaces | Identity user, role, menu and security management | Owning module |
| Module-contributed surfaces | Notification, Audit and future embedded modules | Contributing module |

Every surface must register an ActionDefinition, including reviewed public/protocol surfaces. A route without a registered Action and explicit strategy is an assembly/test failure. A role-authorized Action checks only its same-key Permission; an unknown, retired or disabled definition fails closed. Service, self and operations strategies are validated by their declared identity policy and own no role Permission.

### 5.1 Default Object Actions

Publishing an ObjectSchema invokes one shared `DefaultActionsForObject` policy. Every successfully activated object declares a capability set; an ordinary mutable record surface emits:

- `<object>.create`
- `<object>.read`
- `<object>.update`
- `<object>.delete`
- `<object>.export`

The generator is capability-aware. It omits an operation only when the ObjectSchema explicitly declares that capability unsupported. `system_object` is not a reason to skip authorization. Internal persistence tables that are not ObjectSchema surfaces do not receive permissions.

### 5.2 Built-in Identity Actions

Identity management routes move from raw `HandleFunc(pattern, permissionWrapper(handler))` calls to registered route Actions. Management resources use exact list/get/create/update/delete and semantic command Actions. Because the code has not shipped, old broad `*.write` keys are removed from production definitions and seeds directly; no alias evaluator, compatibility migration, or dual vocabulary is introduced. Route registration and permission reconciliation consume the same definitions.

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
| `operation_key` | display/grouping operation fragment |
| `label` / `description` / `category` | configuration presentation |
| `source_kind` | `platform`, `object_default`, `business_action`, `builtin_surface`, `module_surface` |
| `source_owner` | canonical owner key |
| `definition_status` | `active` or `retired`, controlled by reconciliation |
| `enabled` | administrative runtime switch, preserved by reconciliation |
| `definition_hash` | canonical source-definition hash |
| `source_snapshot_hash` | compare-and-swap hash for the owner's complete reconcile set; not a publication version |
| `created_at` / `updated_at` | audit timestamps |

Unique identity is `(workspace_id, permission_key)`. Permission keys are workspace-global because RoleSchema stores bare permission strings. A conflicting second canonical owner is rejected. Each role-authorized Action owns its same-key Permission; another Action cannot reuse it.

Reconciliation updates source-controlled fields and `definition_status` but never resets an existing `enabled` decision. Missing definitions owned by the reconciled source become `retired`; they are not physically deleted while roles may still reference them. A caller that only references an existing Permission does not become its owner. `previous_snapshot_hash` compare-and-swap rejects out-of-order remote activation.

### 6.2 Add `_identity_applications`

Application authentication registration is separated from authorization metadata. The current row stores workspace/application identity, redirect URLs, status, and timestamps. Service credential secrets remain in the existing secret/config boundary; they are not copied into this table.

### 6.3 Remove catalog tables by direct cutover

Remove:

- `_identity_authorization_catalogs`
- `_identity_authorization_catalog_revisions`

The code has not shipped, so no compatibility adapter or catalog backfill is implemented. Runtime and the SDK switch directly to application registration plus PermissionDefinition reconciliation; the endpoint, store, schema ownership entries, tables, and CatalogRevision field are then deleted in the same refactor.

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

New or changed metadata is not activated until permission reconciliation succeeds. Embedded deployment uses the host database/schema/migration/transaction contracts and the original source-owned relation names; Identity must not inject a `domainry_identity_` relation prefix. The host owns the only `_schema_migrations` ledger, and Identity submits its schema callback through the host migration registrar. Remote deployment uses an idempotent reconciliation API and an activation receipt; it must not expose a new Action before Identity acknowledges the permission snapshot.

### 7.2 Role configuration

`GET /identity/permissions` reads current database PermissionDefinitions. Normal role authoring selects keys from active/enabled definitions and saves them in RoleSchema. Assigned retired/disabled keys remain visible with a warning so administrators can repair roles.

Saving a role rejects unknown keys. Retired or disabled keys cannot be newly selected. Unknown role references never create PermissionDefinitions. Principal construction filters unknown, retired and disabled `RoleSchema.Permissions` before guardrails. Permission-set/group data cannot add a functional Action grant. The filtered RoleSchema is part of the deterministic authorization-revision fingerprint, so disabling a Permission removes it from newly issued AccessBundles without rewriting every RoleSchema.

Role and policy authoring is a direct, versioned RoleSchema boundary rather than a System Change Plan workflow:

- `POST /identity/roles`, `PATCH /identity/roles/{roleID}` and `DELETE /identity/roles/{roleID}` own the exact `identity.roles.create`, `identity.roles.update` and `identity.roles.delete` Actions;
- `PUT /identity/roles/{roleID}/permissions`, `/data-scopes` and `/field-permissions` own separate same-key publish Actions and only replace their corresponding RoleSchema field;
- each command loads the aggregate under its own Action authorization. A publish Action must not acquire the matching list Action as a hidden prerequisite;
- updates require the original schema hash, an idempotency key and a business reason. The repository performs compare-and-swap publication, idempotent replay, audit, role-directory projection and metadata reload as one existing RoleSchema publication flow;
- role creation accepts exact Permission selections. Every selected Permission carries one canonical `data_scope` (`all | owner | org | org_child | target_org`); field, reference, export, delegation and guardrail policies remain separate dedicated authoring boundaries;
- general role update changes display metadata only and preserves all authorization-policy fields. Delete is rejected while user-role or role-menu assignments still reference the role.

There is no role-permission join table, role-authorization draft, approval state machine, or generated aggregate administrator grant. Functional, data and field policy editors may have separate transport DTOs, but all of them publish a new version of the same RoleSchema aggregate.

### 7.3 Request authorization

```text
request/invocation
  -> resolve registered ActionDefinition
  -> authenticate principal
  -> for a role-authorized Action, evaluate its same-key Permission against the current AccessBundle
  -> evaluate data/field/reference/export policy at the owning Runtime
  -> execute or deny and audit
```

The hot path does not parse catalog JSON or Permission usage rows and does not require one database query per request. AccessBundle/authorization snapshots are revisioned and cached. Unknown Action, unknown Permission or stale incompatible policy fails closed.

Permission administration is a read-side exception to the request hot path: `/identity/permissions` joins persisted current PermissionDefinition state with a live, batched Action-registry query. Embedded Runtime binds its frozen registry directly. Standalone Identity calls the Runtime owner endpoint with a short-lived service token restricted to the exact `runtime.authorization.action_usages#query` grant. Browser tokens and ops credentials are not forwarded, responses are never persisted, and an unreachable or unloaded owner is returned as `unavailable` rather than an empty authoritative registry.

### 7.4 No aggregate administrator permission

Identity does not define a reserved workspace-wide administrator Permission. Administrative roles receive an explicit list of same-key Permissions for the Actions they may execute. A request for `identity.users.list`, `customer.read`, or any other Action succeeds only when the role has that exact same-key Permission and its current definition is active and enabled.

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

1. Define their ActionKey, capability/operation labels, Method+router template, page binding and same-key Permission in code.
2. Persist only derived PermissionDefinitions in `_identity_permissions`; Action and URL usage remain a live registry projection.
3. Make `/identity/permissions` combine database Permission state with current Identity Action usages.
4. Update the existing Identity Admin role flow to present capability/operation/Method+URL and directly publish a normal RoleSchema version with schema-hash CAS, idempotency and audit.
5. Run the standalone backend and Vite admin against real APIs, then verify one allowed and one denied management request plus restart persistence.

S0 is historical evidence only. The accepted implementation now proceeds through the full direct cutover and must not preserve Catalog compatibility, aliases, or the earlier broad-permission prototype.

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

### Batch C — application registration and direct Catalog removal

1. Add `_identity_applications` and move redirect validation/application existence checks to it.
2. Move browser and Runtime registration to the application-registration contract.
3. Stop AccessBundle resolution from requiring or filtering through catalog JSON.
4. Delete Catalog APIs and persistence once both direct contracts are wired; do not introduce an adapter.

### Batch D — SDK and Runtime cutover

1. Add application registration and permission reconciliation contracts to the Identity SDK local and remote bindings.
2. Runtime builds one ActionRegistry from Object defaults, authored Actions, endpoint contracts and module contributions.
3. Runtime reconciles PermissionDefinitions before ready and performs final schema-aware policy validation locally.
4. Replace CatalogRevision cache semantics with authorization and metadata revisions.

### Batch E — catalog removal

1. Remove catalog SDK/HTTP APIs and Runtime catalog publisher.
2. Remove `identitycatalog` persistence and catalog policy expansion/filtering.
3. Remove catalog schemas, revisions, indexes, portability specs and tests.
4. Verify fresh-database installation and direct-cutover tests; no historical backfill is required because the code has not shipped.

### Batch F — administration and governance completion

1. Add current Permission enable/disable API with audit; protect the control Action itself without inventing last-admin, reserved-role or wildcard semantics.
2. Update permission UI to show active, disabled and retired states and live Action usage projection.
3. Keep role creation and functional/data/field authorization changes on the direct RoleSchema version path; do not route them through System Change Plan or create a second workflow or versioned Permission publication page.
4. Add governance reports for disabled/retired permissions still referenced by roles.

## 10. Acceptance contract

The refactor is complete only when all of the following hold:

1. Every Identity, Runtime and module surface, including public/protocol surfaces, resolves a registered ActionDefinition with an explicit authorization strategy.
2. Every role-authorized Action's same-key Permission exists as an active PermissionDefinition before the surface is ready; anonymous, authenticated, self, delegated-credential, service and operations Actions use their explicit non-role strategy.
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
14. Role create/update/delete and functional/data/field policy publication use exact same-key Actions and direct RoleSchema CAS publication; no command silently depends on a list Action and no role authorization change uses System Change Plan.

## 11. Explicit non-goals

- Replacing authentication, directory, role-request, access-review or audit business flows.
- Converting Permission keys into literal URLs.
- Persisting Runtime ObjectSchema or Action usage lists in Identity.
- Creating a second role-permission assignment source.
- Rewriting the broader role authoring governance model in the first permission-persistence batch.
