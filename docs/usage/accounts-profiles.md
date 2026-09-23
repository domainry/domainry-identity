# When is a person an Identity user versus a business profile?

## Problems solved

- Separates authentication identity from domain-specific person facts without duplicating credentials or forcing every contact to become a login account.

## Business scenarios

- An employee signs in through Identity while payroll and employment facts live in a one-to-one employee profile.
- A CRM contact or customer representative with no login remains only a project-owned business Object.
- A non-human Workflow or Agent workload uses a managed Service Role rather than a fake employee login.
- Workflow resolves a real manager from Identity reporting-line facts without treating the organization parent as a person manager.

## Use when

Create an Identity user only for a person who authenticates or participates as a governed principal. Bind a project profile when the product owns additional facts.

## Do not use when

Do not turn every customer/contact into a user. Do not copy credentials, session state, Role assignment, or organization membership into a profile Object.

## How to use

Classify account-only, profile-only, or account-plus-binding. Identity owns `identity.user`; the product owns business profile lifecycle; `identity.profile_binding` connects them when supported.

## Adaptation cookbook

| Business requirement | Adapt with | Concrete implementation | Wrong adaptation |
| --- | --- | --- | --- |
| Employee must sign in and also carry payroll and employment facts | Identity account plus a project-owned `employee_profile` with a one-to-one principal reference | Identity owns credentials, login status, and principal ID; the project profile owns employee number, cost center, hire date, and payroll attributes | Putting password, SSO subject, or login status on `employee_profile`, or copying payroll fields onto the Identity account |
| CRM stores a customer contact who never signs in | Project-owned `contact` Object only | Keep name, phone, company, and sales ownership in the CRM domain; create an Identity account later only if interactive access becomes a real requirement | Creating a login account for every contact merely because the record represents a person |
| A user has role-specific facts in more than one domain | One Identity principal referenced by separate owner-specific profiles | Each domain owns its own profile and enforces at most one profile of that type per principal when the business requires it | Creating a second Identity account for each business role or merging unrelated domain facts into a universal person table |
| A Workflow or Agent executes without a human session | Managed service identity and `service` / `system_managed` Role | Bind the workload to the exact allowed Actions and preserve its non-human account type | Creating a shared employee login, storing a password in project settings, or granting administrator authority |
| An approval needs the employee's manager | Identity `manager_user_id` / reporting path through the published resolver | Start from the authenticated user or a declared record user field and resolve an active manager within the configured depth | Assuming an organization node's parent is the employee's manager or copying manager IDs into every Workflow definition |

## Example

Create employee `user-1042` in Identity and bind it one-to-one to project record `employee-1042`. Identity keeps credentials, sessions, account status, organization, manager, and Roles; `employee_profile` keeps employee number, contract, hire date, and payroll facts. Disabling `user-1042` revokes access but does not delete the profile or its historical records. A supplier contact with only an email remains a `contact` Object, and an automated approval worker receives a managed Service Role rather than a human account.

## Permissions and scope

Being bound to a profile does not grant its read/update operations. Roles must include each exact permission with `owner`, `org`, `org_child`, `target_org`, or `all` as appropriate.

## Boundaries

Profile binding requires its published authoring capability. Do not fake it with an undocumented user-ID field.
