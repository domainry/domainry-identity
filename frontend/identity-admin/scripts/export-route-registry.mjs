import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import ts from "typescript";

const root = process.cwd();
const repositoryRoot = path.resolve(root, "../..");
const sourcePath = path.join(root, "src/app-route-registry.ts");
const outputPath = path.join(root, "domainry.frontend-routes.json");

const fail = (message) => {
  console.error(`frontend route registry: ${message}`);
  process.exit(1);
};

const sourceText = fs.readFileSync(sourcePath, "utf8");
const source = ts.createSourceFile(
  sourcePath,
  sourceText,
  ts.ScriptTarget.Latest,
  true,
);
let registry;

const literal = (node) => {
  if (ts.isStringLiteral(node)) return node.text;
  if (ts.isArrayLiteralExpression(node)) return node.elements.map(literal);
  fail(
    `only string and string-array literals are allowed at ${node.getStart(source)}`,
  );
};

const unwrap = (node) =>
  ts.isAsExpression(node) || ts.isSatisfiesExpression(node)
    ? unwrap(node.expression)
    : node;

for (const statement of source.statements) {
  if (!ts.isVariableStatement(statement)) continue;
  for (const declaration of statement.declarationList.declarations) {
    if (
      declaration.name.getText(source) !== "APP_ROUTE_DEFINITIONS" ||
      !declaration.initializer
    )
      continue;
    const initializer = unwrap(declaration.initializer);
    if (!ts.isArrayLiteralExpression(initializer))
      fail("APP_ROUTE_DEFINITIONS must be an array literal");
    registry = initializer.elements.map((element) => {
      const item = unwrap(element);
      if (!ts.isObjectLiteralExpression(item))
        fail("each route must be an object literal");
      const value = {};
      for (const property of item.properties) {
        if (!ts.isPropertyAssignment(property))
          fail("route entries may only contain property assignments");
        const key = property.name.getText(source).replace(/^['"]|['"]$/g, "");
        value[key] = literal(property.initializer);
      }
      return value;
    });
  }
}

if (!registry) fail("APP_ROUTE_DEFINITIONS was not found");

const pagePermissionContractPath = path.join(
  repositoryRoot,
  "frontend/packages/management-contract/src/generated/identity-admin-page-permissions.json",
);
if (!fs.existsSync(pagePermissionContractPath))
  fail(`generated page permission contract does not exist: ${pagePermissionContractPath}`);
const pagePermissionContract = JSON.parse(
  fs.readFileSync(pagePermissionContractPath, "utf8"),
);
if (
  pagePermissionContract.contract_version !== "identity-admin-page-permissions-v1" ||
  !Array.isArray(pagePermissionContract.pages)
)
  fail("generated page permission contract is invalid");
const pagePermissionByRoute = new Map();
for (const page of pagePermissionContract.pages) {
  if (
    !page.route?.startsWith("/") ||
    !page.action_key ||
    page.action_key !== page.permission_key ||
    !page.source_owner ||
    pagePermissionByRoute.has(page.route)
  )
    fail(`generated page permission is invalid or duplicated: ${JSON.stringify(page)}`);
  pagePermissionByRoute.set(page.route, page.permission_key);
}
for (const route of registry) {
  if (route.routeKey === "runtime.admin_home") {
    route.requiredPermissions = [];
    continue;
  }
  const permission = pagePermissionByRoute.get(route.path);
  if (!permission)
    fail(`route ${route.routeKey} has no ActionRegistry page binding for ${route.path}`);
  route.requiredPermissions = [permission];
}

const routeKeys = new Set();
const paths = new Set();
const navKeys = new Set();
for (const [index, route] of registry.entries()) {
  if (!route.routeKey || routeKeys.has(route.routeKey))
    fail(`route ${index} has an empty or duplicate routeKey`);
  if (
    !route.path?.startsWith("/") ||
    route.path.includes("?") ||
    route.path.includes("#") ||
    paths.has(route.path)
  )
    fail(`route ${route.routeKey} has an invalid or duplicate path`);
  if (!["page", "detail"].includes(route.kind))
    fail(`route ${route.routeKey} has unsupported kind ${route.kind}`);
  if (route.navigation !== "platform_admin")
    fail(`route ${route.routeKey} has unsupported navigation ${route.navigation}`);
  if (route.surface !== "admin_console")
    fail(`route ${route.routeKey} has unsupported surface ${route.surface}`);
  if (route.shell !== "admin_console")
    fail(`route ${route.routeKey} has unsupported shell ${route.shell}`);
  if (!route.actorAudiences?.length)
    fail(`route ${route.routeKey} must declare actorAudiences`);
  if (
    route.actorAudiences.length !== 1 ||
    route.actorAudiences[0] !== "platform_admin"
  )
    fail(
      `route ${route.routeKey} must use actor audience platform_admin`,
    );
  if (!Array.isArray(route.requiredPermissions))
    fail(`route ${route.routeKey} must declare requiredPermissions`);
  if (
    route.routeKey !== "runtime.admin_home" &&
    route.requiredPermissions.length === 0
  )
    fail(`production route ${route.routeKey} requires an operation permission`);
  if (!route.routePurpose?.trim())
    fail(`route ${route.routeKey} must declare routePurpose`);
  if (
    !route.featureModule ||
    !fs.existsSync(path.join(root, route.featureModule))
  )
    fail(
      `route ${route.routeKey} feature module does not exist: ${route.featureModule}`,
    );
  if (route.navKey && navKeys.has(route.navKey))
    fail(`route ${route.routeKey} duplicates navKey ${route.navKey}`);
  if (route.kind === "detail" && route.navKey)
    fail(
      `detail route ${route.routeKey} must not declare navKey ${route.navKey}; record detail pages are reached from their owning page`,
    );
  for (const test of route.acceptanceTests ?? []) {
    if (!fs.existsSync(path.join(root, test)))
      fail(`route ${route.routeKey} acceptance test does not exist: ${test}`);
  }
  for (const field of [
    "businessObjects",
    "implementedActions",
    "permissionGatedActions",
    "stateTransitions",
    "createdObjects",
    "writtenFields",
  ]) {
    if (route[field] !== undefined && !Array.isArray(route[field]))
      fail(`route ${route.routeKey} ${field} must be a string array`);
  }
  routeKeys.add(route.routeKey);
  paths.add(route.path);
  if (route.navKey) navKeys.add(route.navKey);
}

// APP_ROUTE_DEFINITIONS page entries with navKey are mounted exactly once by the
// router's pageRoutes loop. A model must map their component in pageForNav;
// declaring another createRoute for the same path produces a TanStack duplicate
// route at runtime even though the exported registry itself is unique.
const routerPath = path.join(root, "src/router.tsx");
const routerText = fs.readFileSync(routerPath, "utf8");
const routerSource = ts.createSourceFile(
  routerPath,
  routerText,
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.TSX,
);
const routeByNavKey = new Map(
  registry.flatMap((route) => (route.navKey ? [[route.navKey, route]] : [])),
);
const explicitPathOwners = new Map();

const resolvedCreateRoutePath = (node) => {
  if (ts.isStringLiteral(node)) return node.text;
  if (
    ts.isPropertyAccessExpression(node) &&
    node.expression.getText(routerSource) === "NAV_PATHS"
  )
    return routeByNavKey.get(node.name.text)?.path;
  if (
    ts.isElementAccessExpression(node) &&
    node.expression.getText(routerSource) === "NAV_PATHS" &&
    node.argumentExpression &&
    ts.isStringLiteral(node.argumentExpression)
  )
    return routeByNavKey.get(node.argumentExpression.text)?.path;
  return undefined;
};

const visitRouter = (node) => {
  if (
    ts.isCallExpression(node) &&
    node.expression.getText(routerSource) === "createRoute" &&
    node.arguments[0] &&
    ts.isObjectLiteralExpression(node.arguments[0])
  ) {
    const pathProperty = node.arguments[0].properties.find(
      (property) =>
        ts.isPropertyAssignment(property) &&
        property.name.getText(routerSource).replace(/^['"]|['"]$/g, "") ===
          "path",
    );
    if (pathProperty && ts.isPropertyAssignment(pathProperty)) {
      const resolvedPath = resolvedCreateRoutePath(pathProperty.initializer);
      if (resolvedPath) {
        const owner = `${routerPath}:${routerSource.getLineAndCharacterOfPosition(pathProperty.getStart(routerSource)).line + 1}`;
        const owners = explicitPathOwners.get(resolvedPath) ?? [];
        explicitPathOwners.set(resolvedPath, [...owners, owner]);
      }
    }
  }
  ts.forEachChild(node, visitRouter);
};
visitRouter(routerSource);

for (const [routePath, owners] of explicitPathOwners) {
  if (owners.length > 1)
    fail(
      `TanStack path ${routePath} has multiple explicit createRoute owners: ${owners.join(", ")}`,
    );
  const registered = registry.find((route) => route.path === routePath);
  if (
    registered?.navKey &&
    registered.kind === "page"
  )
    fail(
      `registered page ${registered.routeKey} (${routePath}) is auto-mounted from NAV_PATHS and must not declare a second createRoute; map ${registered.navKey} in pageForNav instead`,
    );
}

const packageJSON = JSON.parse(
  fs.readFileSync(path.join(root, "package.json"), "utf8"),
);
for (const pageRoute of pagePermissionByRoute.keys()) {
  if (!registry.some((route) => route.path === pageRoute))
    fail(`ActionRegistry page binding ${pageRoute} has no frontend route`);
}
const artifactKind = packageJSON.domainry?.artifact_kind;
const allowedSurfaces = new Set(packageJSON.domainry?.allowed_surfaces ?? []);
if (artifactKind !== "platform_admin")
  fail("package.json domainry.artifact_kind must be platform_admin");
for (const route of registry) {
  if (!allowedSurfaces.has(route.surface))
    fail(
      `platform admin artifact may not own ${route.surface} route ${route.routeKey}`,
    );
}
const productionRegistry = registry;
const output =
  JSON.stringify(
    {
      contract_version: "domainry-frontend-route-registry-v1",
      surface_contract_version: "runtime-surface-contract-v2",
      artifact_kind: artifactKind,
      shell_ownership: "platform_admin",
      frontend_version: `${packageJSON.name}-${packageJSON.version}`,
      routes: productionRegistry.map((route) => ({
        route_key: route.routeKey,
        path: route.path,
        kind: route.kind,
        navigation: route.navigation,
        surface: route.surface,
        feature_module: route.featureModule,
        required_permissions: route.requiredPermissions ?? [],
        required_roles: route.requiredRoles ?? [],
        entrypoint_keys: route.entrypointKeys ?? [],
        business_objects: route.businessObjects ?? [],
        implemented_actions: route.implementedActions ?? [],
        permission_gated_actions: route.permissionGatedActions ?? [],
        state_transitions: route.stateTransitions ?? [],
        created_objects: route.createdObjects ?? [],
        written_fields: route.writtenFields ?? [],
        acceptance_tests: route.acceptanceTests ?? [],
        acceptance_claims: route.acceptanceClaims ?? [],
        route_purpose: route.routePurpose ?? "",
        shell: route.shell,
        exposure_class: "platform_admin",
        high_risk_action_policy: "none",
        shell_ownership: "platform_admin",
        actor_audiences: route.actorAudiences,
        surface_contract: {
          contract_version: "runtime-surface-contract-v2",
          subject_kind: "route",
          identity: route.routeKey,
          surface: route.surface,
          shell: route.shell,
          actor_audiences: route.actorAudiences,
          required_permissions: route.requiredPermissions,
          exposure_class: "platform_admin",
          high_risk_action_policy: "none",
        },
        business_loop_step: route.businessLoopStep ?? "",
        permission_gates: route.permissionGates ?? [],
      })),
    },
    null,
    2,
  ) + "\n";

if (process.argv.includes("--check")) {
  if (
    !fs.existsSync(outputPath) ||
    fs.readFileSync(outputPath, "utf8") !== output
  )
    fail("domainry.frontend-routes.json is stale; run npm run routes:export");
  console.log(`validated ${registry.length} registered frontend routes`);
} else {
  fs.writeFileSync(outputPath, output);
  console.log(
    `exported ${productionRegistry.length} production frontend routes to ${outputPath}`,
  );
}
