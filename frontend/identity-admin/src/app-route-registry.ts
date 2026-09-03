import type {
  FrontendShell,
  FrontendSurface,
  SurfaceAudience,
} from "@domainry/surface-contract";
import pagePermissionContract from "@domainry/identity-management-contract/identity-admin-page-permissions.json";

export type NavKey =
  | "users"
  | "organizationUnits"
  | "roles"
  | "menus"
  | "fieldPerms"
  | "metadata"
  | "audit";

interface AppRouteDefinition {
  routeKey: string;
  navKey?: NavKey;
  path: string;
  kind: "page" | "detail";
  navigation: "platform_admin";
  surface: FrontendSurface;
  featureModule: string;
  requiredRoles?: string[];
  acceptanceTests: string[];
  routePurpose: string;
  shell: FrontendShell;
  actorAudiences: SurfaceAudience[];
}

export interface AppRouteContract extends AppRouteDefinition {
  requiredPermissions: string[];
}

const PAGE_PERMISSION_BY_ROUTE = new Map(
  pagePermissionContract.pages.map((page) => [page.route, page.permission_key]),
);

export const APP_ROUTE_DEFINITIONS = [
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
    acceptanceTests: ["tests/e2e/organization-management.spec.ts"],
  },
  {
    routeKey: "identity.organization_units",
    navKey: "organizationUnits",
    path: "/admin/org/organization-units",
    kind: "page",
    navigation: "platform_admin",
    surface: "admin_console",
    shell: "admin_console",
    actorAudiences: ["platform_admin"],
    routePurpose: "Manage the tenant organization tree and its typed operating nodes.",
    featureModule: "src/features/organization-units/organization-unit-management.tsx",
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
    acceptanceTests: ["tests/e2e/menu-tree-management.spec.ts"],
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
    acceptanceTests: ["src/features/system/audit-explorer-contract.test.ts"],
  },
] as const satisfies readonly AppRouteDefinition[];

export const APP_ROUTE_REGISTRY: readonly AppRouteContract[] = APP_ROUTE_DEFINITIONS.map((route) => {
  if (route.routeKey === "runtime.admin_home") {
    return { ...route, requiredPermissions: [] };
  }
  const permission = PAGE_PERMISSION_BY_ROUTE.get(route.path);
  if (!permission) {
    throw new Error(`Admin page ${route.path} has no ActionRegistry page binding`);
  }
  return { ...route, requiredPermissions: [permission] };
});

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
