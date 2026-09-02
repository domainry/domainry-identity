import {
  createRootRoute,
  createRoute,
  createRouter,
  Navigate,
  Outlet,
  redirect,
  useNavigate,
  useRouterState,
} from '@tanstack/react-router'
import { getStoredSession, useAuth } from '@/lib/auth'
import { useEffectiveMenus, useEffectivePermissions } from '@/data/hooks'
import type { EffectivePermissions } from '@/data/api'
import { LoginPage } from '@/features/auth/login-page'
import { ChangePasswordPage } from '@/features/auth/change-password-page'
import { IdentityCallbackPage } from '@/features/auth/identity-callback-page'
import {
  AdminShell,
  NAV_PATHS,
  type NavKey,
} from '@/features/shell/admin-shell'
import { pageForManagementNav } from '@/app-page-registry'
import { IdentityUserDetailPage } from '@/features/org/identity-user-detail-page'
import { ManagementSurfaceHomePage } from '@/features/shell/management-surface-home'
import {
  isRegisteredMenuPath,
  routeContractForPath,
  routeAccessRequirements,
} from '@/app-route-registry'

const rootRoute = createRootRoute({ component: () => <Outlet /> })

function isEffectiveRouteAllowed(pathname: string, routes: string[]) {
  return routes.some(
    (route) => pathname === route || pathname.startsWith(`${route}/`)
  )
}

function backendEffectivePermissionKeys(snapshot?: EffectivePermissions) {
  const permissions = new Set<string>()
  for (const item of snapshot?.function_permissions ?? []) {
    if (item.decision.allowed) permissions.add(item.key)
  }
  return [...permissions]
}

export function isRouteAllowed(
  pathname: string,
  routes: string[],
  permissions: string[] = [],
  roles: string[] = [],
) {
  const routeContract = routeContractForPath(pathname)
  const { requiredPermissions, requiredRoles } = routeAccessRequirements(pathname)
  const contractAllowed = requiredPermissions.every((permission) => permissions.includes(permission))
    && (requiredRoles.length === 0 || requiredRoles.some((role) => roles.includes(role)))
  return routeContract?.surface === 'admin_console' && (
    contractAllowed || isEffectiveRouteAllowed(pathname, routes)
  )
}

const loginSearch = (search: Record<string, unknown>): { redirect?: string } => ({
  redirect: typeof search.redirect === 'string' ? search.redirect : undefined,
})

const adminLoginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/admin/login',
  validateSearch: loginSearch,
  component: AdminLoginScreen,
})

const adminChangePasswordRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/admin/change-password',
  component: ChangePasswordScreen,
})

const identityCallbackRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/auth/callback',
  component: IdentityCallbackPage,
})

function AdminLoginScreen() {
  const { redirect: target } = adminLoginRoute.useSearch()
  return <LoginScreen target={target} />
}

function LoginScreen({ target }: { target?: string }) {
  const { session } = useAuth()
  const canLoadNavigation = Boolean(session && !session.mustChangePassword)
  const { data: menus = [], isSuccess } = useEffectiveMenus(canLoadNavigation)
  const effectivePermissions = useEffectivePermissions(undefined, canLoadNavigation)
  if (session?.mustChangePassword) return <Navigate to='/admin/change-password' replace />
  if (session && isSuccess && effectivePermissions.isSuccess) {
    const permissionKeys = backendEffectivePermissionKeys(effectivePermissions.data)
    const candidateRoutes = menus.flatMap((menu) => (
      menu.route && isRegisteredMenuPath(menu.route) ? [menu.route] : []
    ))
    const roleKeys = session.roles.map((role) => role.key)
    const routes = candidateRoutes.filter((route) => isRouteAllowed(
      route,
      candidateRoutes,
      permissionKeys,
      roleKeys,
    ))
    const destination = target && isRouteAllowed(
      target.split('?')[0],
      routes,
      permissionKeys,
      roleKeys,
    ) ? target : routes[0]
    if (destination) return <Navigate to={destination} replace />
  }
  if (session) return <Navigate to='/admin' replace />
  return <LoginPage />
}

function ChangePasswordScreen() {
  const { session } = useAuth()
  const navigate = useNavigate()
  if (!session) return <Navigate to='/admin/login' replace />
  if (!session.mustChangePassword) return <Navigate to='/admin' replace />
  return <ChangePasswordPage onSuccess={() => void navigate({ to: '/admin', replace: true })} />
}

const shellRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'shell',
  beforeLoad: ({ location }) => {
    const session = getStoredSession()
    if (!session) {
      throw redirect({ to: '/admin/login', search: { redirect: location.href } })
    }
    if (session.mustChangePassword) {
      throw redirect({ to: '/admin/change-password' })
    }
  },
  component: ShellLayout,
})

function ShellLayout() {
  const { session } = useAuth()
  const pathname = useRouterState({ select: (state) => state.location.pathname })
  const canLoadNavigation = Boolean(session && !session.mustChangePassword)
  const { data: menus = [], isSuccess } = useEffectiveMenus(canLoadNavigation)
  const effectivePermissions = useEffectivePermissions(undefined, canLoadNavigation)
  if (!session) return <Navigate to='/admin/login' replace />
  if (session.mustChangePassword) return <Navigate to='/admin/change-password' replace />
  if (isSuccess && effectivePermissions.isSuccess) {
    const permissionKeys = backendEffectivePermissionKeys(effectivePermissions.data)
    const candidateRoutes = menus.flatMap((menu) => (
      menu.route && isRegisteredMenuPath(menu.route) ? [menu.route] : []
    ))
    const roleKeys = session.roles.map((role) => role.key)
    const routes = candidateRoutes.filter((route) => isRouteAllowed(
      route,
      candidateRoutes,
      permissionKeys,
      roleKeys,
    ))
    if (!isRouteAllowed(pathname, routes, permissionKeys, roleKeys) && routes[0]) {
      return <Navigate to={routes[0]} replace />
    }
  }
  return <AdminShell><Outlet /></AdminShell>
}

const indexRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: '/',
  component: RuntimeHomeRedirect,
})

const adminHomeRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: '/admin',
  component: ManagementHome,
})

function RuntimeHomeRedirect() {
  const { data: menus = [] } = useEffectiveMenus()
  const target = menus.find((menu) => menu.route && isRegisteredMenuPath(menu.route))?.route
  return target ? <Navigate to={target} replace /> : <NavigationContractError />
}

function ManagementHome() {
  const { session } = useAuth()
  const { data: menus = [] } = useEffectiveMenus()
  const effectivePermissions = useEffectivePermissions()
  if (!session) return <NavigationContractError />
  const candidateRoutes = menus.flatMap((menu) => (
    menu.route
    && isRegisteredMenuPath(menu.route)
    && routeContractForPath(menu.route)?.surface === 'admin_console'
      ? [menu.route]
      : []
  ))
  const roleKeys = session.roles.map((role) => role.key)
  const permissionKeys = backendEffectivePermissionKeys(effectivePermissions.data)
  const target = candidateRoutes.find((route) => isRouteAllowed(
    route,
    candidateRoutes,
    permissionKeys,
    roleKeys,
  ))
  return target ? <ManagementSurfaceHomePage surface='admin_console' /> : <NavigationContractError />
}

function NavigationContractError() {
  return <main className='grid min-h-screen place-items-center p-6'><div className='max-w-lg rounded-lg border p-6'><h1 className='text-lg font-semibold'>Navigation configuration is incomplete</h1><p className='mt-2 text-sm text-muted-foreground'>No accessible Identity menu is linked to an implemented frontend page.</p></div></main>
}

const identityUserDetailRoute = createRoute({
  getParentRoute: () => shellRoute,
  path: '/admin/security/accounts/$userId',
  component: IdentityUserDetailScreen,
})

function IdentityUserDetailScreen() {
  const { userId } = identityUserDetailRoute.useParams()
  return <IdentityUserDetailPage userID={userId} />
}

const PAGE_KEYS = Object.keys(NAV_PATHS) as NavKey[]
const pageRoutes = PAGE_KEYS.map((key) => createRoute({
  getParentRoute: () => shellRoute,
  path: NAV_PATHS[key],
  component: pageForManagementNav(key),
}))

const routeTree = rootRoute.addChildren([
  adminLoginRoute,
  adminChangePasswordRoute,
  identityCallbackRoute,
  shellRoute.addChildren([
    indexRoute,
    adminHomeRoute,
    identityUserDetailRoute,
    ...pageRoutes,
  ]),
])

export const router = createRouter({
  routeTree,
  defaultNotFoundComponent: NavigationContractError,
})
