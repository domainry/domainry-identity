import type {
  FrontendShell,
  FrontendSurface,
  SurfaceAudience,
} from "@domainry/surface-contract";

export type NavKey =
  | "users"
  | "workforce"
  | "departments"
  | "roles"
  | "menus"
  | "dataScopes"
  | "fieldPerms"
  | "metadata"
  | "audit";

export interface AppRouteContract {
  routeKey: string;
  navKey?: NavKey;
  path: string;
  kind: "page" | "detail";
  navigation: "platform_admin";
  surface: FrontendSurface;
  featureModule: string;
  requiredPermissions: string[];
  requiredRoles?: string[];
  acceptanceTests: string[];
  routePurpose: string;
  shell: FrontendShell;
  actorAudiences: SurfaceAudience[];
}

export const APP_ROUTE_REGISTRY = [
  {
    routeKey: "runtime.admin_home",
    path: "/admin",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Resolve an authenticated user to the Identity Admin Console shell.",
    featureModule: "src/router.tsx",
    requiredPermissions: [],
    acceptanceTests: ["tests/e2e/organization-management.spec.ts"],
  },
  {
    routeKey: "identity.users",
    navKey: "users",
    path: "/admin/security/accounts",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage tenant login accounts and account security.",
    featureModule: "src/features/org/identity-accounts-page.tsx",
    requiredPermissions: ["identity.users.read"],
    acceptanceTests: ["tests/e2e/organization-management.spec.ts"],
  },
  {
    routeKey: "identity.user_detail",
    path: "/admin/security/accounts/$userId",
    kind: "detail",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Review one tenant login account and its security state.",
    featureModule: "src/features/org/identity-user-detail-page.tsx",
    requiredPermissions: ["identity.users.read"],
    acceptanceTests: ["tests/e2e/organization-management.spec.ts"],
  },
  {
    routeKey: "identity.workforce",
    navKey: "workforce",
    path: "/admin/org/workforce",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage tenant workforce profiles and assignments.",
    featureModule: "src/features/org/workforce-page.tsx",
    requiredPermissions: ["identity.workforce.read"],
    acceptanceTests: ["src/features/org/workforce-page.test.ts"],
  },
  {
    routeKey: "identity.workforce_detail",
    path: "/admin/org/workforce/$profileID",
    kind: "detail",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Review one Workforce profile and its effective assignments.",
    featureModule: "src/features/org/workforce-detail-page.tsx",
    requiredPermissions: ["identity.workforce.read"],
    acceptanceTests: ["src/features/org/workforce-detail-page.test.ts"],
  },
  {
    routeKey: "identity.departments",
    navKey: "departments",
    path: "/admin/org/departments",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage tenant organization departments.",
    featureModule: "src/features/departments/department-management.tsx",
    requiredPermissions: ["identity.departments.read"],
    acceptanceTests: ["tests/e2e/organization-management.spec.ts"],
  },
  {
    routeKey: "identity.roles",
    navKey: "roles",
    path: "/admin/org/roles",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Govern tenant roles and effective access.",
    featureModule: "src/features/org/roles.tsx",
    requiredPermissions: ["identity.roles.read"],
    acceptanceTests: ["tests/e2e/role-server-search.spec.ts"],
  },
  {
    routeKey: "identity.menus",
    navKey: "menus",
    path: "/admin/org/menus",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage tenant navigation definitions.",
    featureModule: "src/features/org/menus.tsx",
    requiredPermissions: ["identity.menus.read"],
    acceptanceTests: ["tests/e2e/menu-tree-management.spec.ts"],
  },
  {
    routeKey: "identity.data_scopes",
    navKey: "dataScopes",
    path: "/admin/org/data-scopes",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage tenant record data-scope policies.",
    featureModule: "src/features/org/data-scopes.tsx",
    requiredPermissions: ["identity.data_scopes.read"],
    acceptanceTests: ["tests/e2e/data-scopes-layout.spec.ts"],
  },
  {
    routeKey: "identity.field_permissions",
    navKey: "fieldPerms",
    path: "/admin/org/field-permissions",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage tenant field access policies.",
    featureModule: "src/features/org/field-permissions.tsx",
    requiredPermissions: ["identity.field_permissions.read"],
    acceptanceTests: ["tests/e2e/business-configuration-surfaces.spec.ts"],
  },
  {
    routeKey: "system.metadata",
    navKey: "metadata",
    path: "/admin/system/metadata",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage tenant Metadata definitions and revisions used by Identity authorization.",
    featureModule: "src/features/system/metadata.tsx",
    requiredPermissions: ["metadata.read"],
    acceptanceTests: ["tests/e2e/business-configuration-surfaces.spec.ts"],
  },
  {
    routeKey: "identity.governance_audit",
    navKey: "audit",
    path: "/admin/system/audit",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Review Identity governance and security audit history.",
    featureModule: "src/features/system/audit.tsx",
    requiredPermissions: ["audit.governance.read"],
    acceptanceTests: ["src/features/system/audit-explorer-contract.test.ts"],
  },
] as const satisfies readonly AppRouteContract[];

export const NAV_PATHS = Object.fromEntries(
  (APP_ROUTE_REGISTRY as readonly AppRouteContract[]).flatMap((route) =>
    route.navKey ? [[route.navKey, route.path]] : [],
  ),
) as Record<NavKey, string>;

export const REGISTERED_APP_PATHS = new Set<string>(
  APP_ROUTE_REGISTRY.map((route) => route.path),
);

function routePathMatches(routePath: string, pathname: string) {
  const routeSegments = routePath.split("/").filter(Boolean);
  const pathSegments = pathname.split("/").filter(Boolean);
  if (routeSegments.length !== pathSegments.length) return false;
  return routeSegments.every((segment, index) =>
    segment.startsWith("$") ? Boolean(pathSegments[index]) : segment === pathSegments[index]
  );
}

export function routeContractForPath(pathname: string) {
  return (APP_ROUTE_REGISTRY as readonly AppRouteContract[])
    .filter((route) => routePathMatches(route.path, pathname))
    .sort((left, right) => {
      const leftDynamic = left.path.split("/").filter((segment) => segment.startsWith("$")).length;
      const rightDynamic = right.path.split("/").filter((segment) => segment.startsWith("$")).length;
      return leftDynamic - rightDynamic || right.path.length - left.path.length;
    })[0];
}

export function routeAccessRequirements(pathname: string) {
  const route = routeContractForPath(pathname) as AppRouteContract | undefined;
  return {
    requiredPermissions: route?.requiredPermissions ?? [],
    requiredRoles: route?.requiredRoles ?? [],
  };
}

export function isRegisteredMenuPath(pathname: string) {
  return REGISTERED_APP_PATHS.has(pathname);
}
