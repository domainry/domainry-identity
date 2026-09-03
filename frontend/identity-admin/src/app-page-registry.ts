import type { FunctionComponent } from "react";
import type { NavKey } from "@/app-route-registry";
import { OrganizationUnitManagementPage } from "@/features/organization-units/organization-unit-management";
import { IdentityAccountsPage } from "@/features/org/identity-accounts-page";
import { RolesPage } from "@/features/org/roles";
import { MenuManagementPage } from "@/features/org/menus";
import { FieldPermissionsPage } from "@/features/org/field-permissions";
import { MetadataPage } from "@/features/system/metadata";
import { AuditPage } from "@/features/system/audit";

const MANAGEMENT_PAGES: Record<NavKey, FunctionComponent> = {
  users: IdentityAccountsPage,
  organizationUnits: OrganizationUnitManagementPage,
  roles: RolesPage,
  menus: MenuManagementPage,
  fieldPerms: FieldPermissionsPage,
  metadata: MetadataPage,
  audit: AuditPage,
};

export function pageForManagementNav(key: NavKey): FunctionComponent {
  return MANAGEMENT_PAGES[key];
}
