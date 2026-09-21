# When should company structure use Identity organization units?

## Problems solved

- Provides one authoritative hierarchy for principal placement and organization-scoped authorization instead of copying region or department trees into projects.

## Business scenarios

- Regional managers access stores in their organization subtree.
- Employees are placed into departments, branches, warehouses, or operating units that determine access boundaries.
- A transferred employee's new requests use the new organization scope while old records retain their recorded owning organization.
- A project team or product taxonomy remains a project concept unless it truly becomes a principal-placement or authorization boundary.

## Use when

Use Identity organization units when hierarchy places users or drives `org`, `org_child`, or `target_org` authorization.

## Do not use when

Do not use Identity for CRM companies, categories, cost classifications, or other trees that do not govern principal placement/access.

## How to use

Keep one authoritative organization tree in Identity. Bind a project-owned organization profile only for extra business facts; never copy parent/child structure.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Regional managers may operate all stores below their region | Identity organization hierarchy plus `org_child` data scope | Model region and store as organization units, place users in the authoritative unit, and grant the manager permission over descendants | Copying region/store IDs into every Role or calculating the hierarchy independently inside each project Handler |
| Store employees may access only records owned by their store | Identity organization placement plus `org` data scope | Business rows carry the authoritative owning organization ID; authorization resolves the principal's current organization from Identity | Treating a free-text branch field or frontend filter as an access boundary |
| CRM needs companies and customer accounts for sales work | Project-owned customer/company Objects | Keep commercial lifecycle, addresses, account tier, and sales relationships in the CRM domain; reference an Identity organization only when it truly controls principal placement or authorization | Modeling every customer company as an Identity organization even though no users or access policies belong to it |
| A warehouse needs operational attributes in addition to access placement | Identity organization unit plus owner-specific organization profile | Identity owns the hierarchy node and placement semantics; the warehouse profile owns capacity, operating hours, and fulfillment settings | Adding all warehouse business columns to the shared Identity organization record |
| An employee transfers from Store A to Store B | Identity user placement update | New authorization context resolves Store B; keep historical records' Runtime-owned `owner_org_id` unchanged unless an explicit business Operation transfers ownership | Bulk rewriting history on login or leaving a stale copied organization path in the profile |
| A temporary project squad groups people but does not define row access | Project membership Object/Relation | Keep the team's lifecycle and membership in the owning business domain | Adding a parallel Identity branch solely because the UI calls it a team |

## Example

Model `company-cn -> region-east -> store-shanghai-01` once in Identity. Place the store employee at `store-shanghai-01` and the regional manager at `region-east`; grant order read with `org` and `org_child` respectively. Store hours and sales target stay on a related project store profile. When the employee transfers, new requests use the new Principal scope, but existing orders keep their original owning organization. Disabling a node blocks new active use and must respect children/assignments; an unauthorized caller cannot create, move, or disable a node outside its exact permission and scope.

## Permissions and scope

`org` covers the actor’s organization node; `org_child` includes its descendants; `target_org` is a trusted service assignment, never a caller-chosen ID.

## Boundaries

Reporting lines are personnel relationships, not organization hierarchy. Organizations and live assignments remain Identity-owned capabilities.
