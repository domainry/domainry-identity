# When is a person an Identity user versus a business profile?

## Problems solved

- Separates authentication identity from domain-specific person facts without duplicating credentials or forcing every contact to become a login account.

## Business scenarios

- An employee signs in through Identity while payroll and employment facts live in a one-to-one employee profile.
- A CRM contact or customer representative with no login remains only a project-owned business Object.

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

## Example

An employee who signs in and has payroll-specific facts uses Identity plus an employee profile. A CRM contact who never signs in is only a product Object.

## Permissions and scope

Being bound to a profile does not grant its read/update operations. Roles must include each exact permission with `owner`, `org`, `org_child`, `target_org`, or `all` as appropriate.

## Boundaries

Profile binding requires its published authoring capability. Do not fake it with an undocumented user-ID field.
