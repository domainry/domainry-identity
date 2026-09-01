import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import {
  Activity,
  ArrowRight,
  Building2,
  Database,
  ShieldCheck,
  Users,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@domainry/ui";
import { PageShell } from "@/components/page-shell";
import { StatCard, StatGrid } from "@/components/stat-card";
import { StatusBadge } from "@/components/status-badge";
import {
  departmentsApi,
  identityAccountsApi,
  identityServiceApi,
  objectsApi,
  rolesApi,
} from "@/data/api";
import { useEffectiveMenus } from "@/data/hooks";
import { routeContractForPath } from "@/app-route-registry";
import { useI18n } from "@/lib/i18n";
import { usePermissions } from "@/lib/permissions";
import { systemMenuLabel } from "@/lib/system-menu-label";

type ManagementSurface = "admin_console";

export function ManagementSurfaceHomePage({
  surface,
}: {
  surface: ManagementSurface;
}) {
  const { t } = useI18n();
  const { has, ready } = usePermissions();
  const { data: menus = [] } = useEffectiveMenus();
  const health = useQuery({
    queryKey: ["identity", "management-home", surface, "health"],
    queryFn: identityServiceApi.health,
  });
  const schema = useQuery({
    queryKey: ["identity", "management-home", "schema"],
    queryFn: objectsApi.schemaSnapshot,
    enabled: ready && has("identity.metadata.manifest.get"),
  });
  const accounts = useQuery({
    queryKey: ["identity", "management-home", "accounts"],
    queryFn: identityAccountsApi.list,
    enabled: ready && has("identity.users.list"),
  });
  const departments = useQuery({
    queryKey: ["identity", "management-home", "departments"],
    queryFn: departmentsApi.list,
    enabled: ready && has("identity.departments.list"),
  });
  const roles = useQuery({
    queryKey: ["identity", "management-home", "roles"],
    queryFn: rolesApi.list,
    enabled: ready && has("identity.roles.list"),
  });

  const visibleMenus = menus.filter((menu) => {
    if (!menu.route) return false;
    return routeContractForPath(menu.route)?.surface === surface;
  });
  const adminStats = [
    {
      label: t("managementHome.admin.accounts"),
      value: queryCount(accounts.data?.length, accounts.isPending),
      delta: t("managementHome.admin.accountsHint"),
    },
    {
      label: t("managementHome.admin.departments"),
      value: queryCount(departments.data?.length, departments.isPending),
      delta: t("managementHome.admin.departmentsHint"),
    },
    {
      label: t("managementHome.admin.roles"),
      value: queryCount(roles.data?.length, roles.isPending),
      delta: t("managementHome.admin.rolesHint"),
    },
    {
      label: t("managementHome.admin.objects"),
      value: queryCount(schema.data?.objects?.length, schema.isPending),
      delta: t("managementHome.admin.objectsHint"),
    },
  ];

  return (
    <PageShell
      title={t("managementHome.admin.title")}
      description={t("managementHome.admin.description")}
    >
      <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-card px-4 py-3">
        <Activity className="size-4" />
        <span className="text-sm font-medium">{t("managementHome.runtimeHealth")}</span>
        <StatusBadge
          value={health.data?.status === "ok" ? "success" : "warning"}
        >
          {health.data?.status ?? t("managementHome.loading")}
        </StatusBadge>
      </div>

      <StatGrid className="lg:grid-cols-4">
        {adminStats.map((stat) => (
          <StatCard key={stat.label} {...stat} />
        ))}
      </StatGrid>

      <Card>
        <CardHeader>
          <CardTitle>{t("managementHome.authorizedTasks")}</CardTitle>
          <CardDescription>
            {t("managementHome.authorizedTasksDescription")}
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {visibleMenus.map((menu) => (
            <Link
              key={menu.id}
              to={menu.route as never}
              className="group flex min-h-24 items-center gap-3 rounded-lg border p-4 transition-colors hover:bg-muted/45"
            >
              <MenuIcon route={menu.route ?? ""} />
              <div className="min-w-0 flex-1">
                <p className="truncate font-medium">{systemMenuLabel(t, menu.key, menu.label)}</p>
                <code className="mt-1 block truncate text-xs text-muted-foreground">
                  {menu.route}
                </code>
              </div>
              <ArrowRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
            </Link>
          ))}
        </CardContent>
      </Card>
    </PageShell>
  );
}

function queryCount(value: number | undefined, pending: boolean) {
  if (pending) return "…";
  return value === undefined ? "—" : String(value);
}

function MenuIcon({ route }: { route: string }) {
  if (route.includes("accounts") || route.includes("workforce")) return <Users className="size-5" />;
  if (route.includes("departments")) return <Building2 className="size-5" />;
  if (route.includes("roles") || route.includes("permissions")) return <ShieldCheck className="size-5" />;
  return <Database className="size-5" />;
}
