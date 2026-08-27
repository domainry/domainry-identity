import type { FunctionComponent } from "react";
import type { NavKey } from "@/app-route-registry";
import { DepartmentManagementPage } from "@/features/departments/department-management";
import { IdentityAccountsPage } from "@/features/org/identity-accounts-page";
import { WorkforcePage } from "@/features/org/workforce-page";
import { RolesPage } from "@/features/org/roles";
import { MenuManagementPage } from "@/features/org/menus";
import { DataScopesPage } from "@/features/org/data-scopes";
import { FieldPermissionsPage } from "@/features/org/field-permissions";
import { MetadataPage } from "@/features/system/metadata";
import { AuditPage } from "@/features/system/audit";

const MANAGEMENT_PAGES: Record<NavKey, FunctionComponent> = {
  users: IdentityAccountsPage,
  workforce: WorkforcePage,
  departments: DepartmentManagementPage,
  roles: RolesPage,
  menus: MenuManagementPage,
  dataScopes: DataScopesPage,
  fieldPerms: FieldPermissionsPage,
  metadata: MetadataPage,
  audit: AuditPage,
};

export function pageForManagementNav(key: NavKey): FunctionComponent {
  return MANAGEMENT_PAGES[key];
}
