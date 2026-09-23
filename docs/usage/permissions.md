# How should Roles, exact permissions, and data scopes be modeled?

## Problems solved

- Converts business authority into exact operation grants and truthful row scopes instead of relying on frontend visibility or broadly named Roles.

## Business scenarios

| Business requirement | Data scope | Runtime row boundary | Do not choose it when |
| --- | --- | --- | --- |
| A central finance or audit Role works across all matching rows in one Workspace. | `all` | Workspace isolation and caller filters still apply, but no narrower Role predicate is added. | Ownership is unclear or access is intended to cross Workspaces. |
| Sales representatives update only records they own while regional managers read one organization subtree. | `owner` for the representative; `org_child` for the manager | `owner` matches immutable `owner_user_id`; `org_child` matches the principal's Identity-issued organization subtree. | “Owner” means a mutable assignee, or the manager needs personnel reporting-line rather than organization-tree access. |
| Store staff work only with orders owned by their own store. | `org` | `owner_org_id` equals the principal's current organization. | The Role also needs child stores or a separately assigned service organization. |
| A regional manager reads the region and all descendant stores. | `org_child` | `owner_org_id` belongs to the principal's current organization subtree. | Direct reports are not represented by that organization tree. |
| A service Role operates only on a trusted target organization and selected menus or fields remain separately governed. | `target_org` | `owner_org_id` belongs to the Identity-issued trusted support subtree. | The target organization comes from request input or no trusted support assignment exists. |
| A case is visible when its related customer belongs to one of the actor's organization-scope IDs. | `data_policy` | Runtime follows a schema-validated relation path and compares the target field with an allowlisted Identity subject claim. | A built-in scope already expresses the rule, or the value would come from request input, SQL, or an arbitrary claim. |

## Use when

Use a Role entry for every confirmed audience that needs a stable set of exact operations and row scopes.

## Do not use when

Do not infer authorization from menu visibility, Role name, seniority, or frontend routes. Do not invent wildcard permissions or custom scope strings.

## How to use

1. List each exact operation independently: read, create, update, delete, export, and every named Business Operation are separate permissions.
2. Identify the real row boundary for that operation, not the screen name or Role seniority.
3. Choose exactly one built-in `data_scope` (`all`, `owner`, `org`, `org_child`, or `target_org`) when it expresses the boundary. Otherwise declare exactly one closed `data_policy`; never set both.
4. A `data_policy` is a bounded AST: boolean `and`/`or`/`not`, or an `eq`/`in` leaf with at most three acyclic `forward`/`reverse` relation segments, one schema-bound field, and one allowlisted subject claim. It cannot contain literals, SQL, request context, callbacks, or arbitrary claims.
5. Declare the Role in `domainry.model/v3`; Identity owns live users and assignments, while Runtime evaluates the exact grant on every request.
6. If one human Role is the initial Workspace administrator, reference that Role from `project.initial_workspace_administrator_role`; Runtime owns Workspace creation and first assignment.
7. Verify one allowed call, one call without the exact permission, one out-of-scope row, and unchanged durable state after a rejected write.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| A salesperson reads and updates only personally owned leads. | `lead.read;owner` and `lead.update;owner` | Grant both exact permissions with `data_scope: "owner"`; create the lead under the principal whose immutable Runtime owner should control it. | Granting `all`, filtering by `assignee_id` in the browser, or assuming update follows from read. |
| Store staff operate only their own store's orders. | `sales_order.*;org` per required operation | Place the principal in the store organization and ensure Runtime-owned `owner_org_id` is that store for created orders. | Passing `store_id` from the request as authorization or copying the organization path into project fields. |
| A regional manager reads all child-store orders but may approve only assigned cases. | `sales_order.read;org_child` plus `case.approve;owner` | Choose scope independently per exact permission; organization-wide read does not widen approval authority. | Applying one Role-wide scope to every operation. |
| Shared support serves one sales region while remaining in the Support organization. | `customer.read;target_org` | Identity assigns a trusted support root; Runtime derives its subtree. Keep the actor's real home organization unchanged. | Changing the actor's home organization, accepting a caller-selected organization ID, or silently using `all`. |
| An order is readable only when its related customer belongs to the actor's organization subtree. | Relational `data_policy` | On `order.read`, follow `customer_id` forward to `customer`, then compare `organization_id` with `org_scope_ids` using `in`; Runtime and Identity both validate the relation path. | Loading all orders and filtering in application code, embedding SQL, or trusting a caller-supplied organization list. |
| A sensitive note is readable but never writable or exportable by one Role. | Exact field policy plus the Object permission | Grant Object access and separately publish the field's read/write/export/masking policy through Identity's field-permission contract. | Treating menu visibility or Object read permission as field authority. |
| Every new Workspace needs the same first human administrator Role. | `project.initial_workspace_administrator_role` referencing a declared Role | Declare the reviewed Role once and let Runtime provision and assign it idempotently when the Workspace is created. | Creating a tenant Object, provisioning users in a Handler, or making a service Role the human administrator. |

## Example

```json
{
  "schema_version": "domainry.model/v3",
  "project": {
    "initial_workspace_administrator_role": "workspace_admin"
  },
  "roles": [
    {"key":"workspace_admin","name":"Workspace administrator","audience":"user","assignment_mode":"manual","provision_to_workspaces":true,"permissions":[{"permission_key":"lead.read","data_scope":"all"},{"permission_key":"lead.update","data_scope":"all"}]},
    {"key":"sales_rep","name":"Sales representative","audience":"user","assignment_mode":"manual","permissions":[{"permission_key":"lead.read","data_scope":"owner"},{"permission_key":"lead.update","data_scope":"owner"}]},
    {"key":"store_operator","name":"Store operator","audience":"user","assignment_mode":"manual","permissions":[{"permission_key":"sales_order.read","data_scope":"org"},{"permission_key":"sales_order.update","data_scope":"org"}]},
    {"key":"regional_manager","name":"Regional manager","audience":"user","assignment_mode":"manual","permissions":[{"permission_key":"lead.read","data_scope":"org_child"}]},
    {"key":"customer_scope_reviewer","name":"Customer scope reviewer","audience":"user","assignment_mode":"manual","permissions":[{"permission_key":"sales_order.read","data_policy":{"operator":"in","path":[{"direction":"forward","relation_field_key":"customer","target_object_key":"customer"}],"field_key":"organization_id","subject_claim":"org_scope_ids"}}]},
    {"key":"support_service","name":"Support service","audience":"service","assignment_mode":"system_managed","permissions":[{"permission_key":"lead.read","data_scope":"target_org"}]},
    {"key":"finance_operator","name":"Finance operator","audience":"user","assignment_mode":"manual","permissions":[{"permission_key":"invoice.read","data_scope":"all"},{"permission_key":"invoice.export","data_scope":"all"}]}
  ]
}
```

`owner` means Runtime’s immutable creator, not a mutable assignee. Reassignment requirements need a truthful organization boundary, a schema-bound relational `data_policy`, or a named Operation that validates the assignee inside wider authorized scope.

## Permissions and scope

Read, create, update, delete, export, and named Operations never imply one another. Scope is storage-bound: Runtime combines it with caller filters for reads and keeps it on atomic mutations. Application-side filtering of unscoped rows is never authorization evidence.

Verification must cover:

- allowed Role + exact permission + in-scope row succeeds;
- missing permission or Role assignment is function-denied;
- exact permission + out-of-scope row is row-denied;
- mixed allowed/out-of-scope mutation batches fail together;
- a rejected mutation leaves durable state unchanged;
- field, reference, menu, and export policy are verified separately when used.

## Boundaries

Field permissions, menus, users, and live Role assignment are separate Identity-owned capabilities. Relational policies are capped at depth 8 and 64 AST nodes, and relation paths at three segments; cycles and disabled or mismatched relation fields fail publication. Do not translate old Builder compact-map examples into `domainry.model/v3` JSON.
