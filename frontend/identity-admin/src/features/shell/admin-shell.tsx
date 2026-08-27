import {
  useEffect,
  useMemo,
  useState,
  type ComponentType,
  type ReactNode,
} from "react";
import { Link, useRouter, useRouterState } from "@tanstack/react-router";
import {
  Braces,
  BriefcaseBusiness,
  Building2,
  Languages,
  LogOut,
  Moon,
  Palette as PaletteIcon,
  Search,
  ScrollText,
  ShieldCheck,
  SquareMenu,
  Sun,
  User as UserIcon,
  Users,
} from "lucide-react";
import { PendingSystemDrafts } from "@/features/system/pending-system-drafts";
import { PRODUCT_BRAND } from "@/config/product-brand";
import { ProductBrandMark } from "@/components/product-brand-mark";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Avatar,
  AvatarFallback,
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
  Button,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Separator,
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarRail,
  SidebarTrigger,
} from "@domainry/ui";
import { useTheme, type Palette } from "@/context/theme-provider";
import { useAuth } from "@/lib/auth";
import {
  useDepartments,
  useEffectiveMenus,
  useUsers,
} from "@/data/hooks";
import { displayText } from "@/data/text";
import { PageErrorBoundary } from "@/components/page-error-boundary";
import { LOCALES, useI18n, type Locale, type MessageKey } from "@/lib/i18n";
import { systemMenuLabel } from "@/lib/system-menu-label";
import { cn } from "@/lib/utils";
import {
  NAV_PATHS,
  isRegisteredMenuPath,
  type NavKey,
} from "@/app-route-registry";

/* ------------------------------------------------------------------ */
/* Navigation registry                                                 */
/* ------------------------------------------------------------------ */

export type { NavKey } from "@/app-route-registry";

interface NavItem {
  key: NavKey;
  labelKey: MessageKey;
  icon: ComponentType<{ className?: string }>;
}

interface NavGroup {
  labelKey: MessageKey;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    labelKey: "nav.group.org",
    items: [
      { key: "users", labelKey: "nav.users", icon: Users },
      { key: "workforce", labelKey: "nav.workforce", icon: BriefcaseBusiness },
      { key: "departments", labelKey: "nav.departments", icon: Building2 },
      { key: "roles", labelKey: "nav.roles", icon: ShieldCheck },
      { key: "menus", labelKey: "nav.menus", icon: SquareMenu },
    ],
  },
  {
    labelKey: "nav.group.system",
    items: [
      { key: "metadata", labelKey: "nav.metadata", icon: Braces },
      { key: "audit", labelKey: "nav.audit", icon: ScrollText },
    ],
  },
];

export const DEV_NAV_KEYS = [] as const;

/**
 * Route paths per nav entry. Kept aligned with the seed data in the menu
 * management page so configured menu paths match real routes.
 */
export { NAV_PATHS } from "@/app-route-registry";

export function isDevelopmentPath(_pathname: string) {
  return false;
}

function navKeyFromPath(pathname: string): NavKey {
  const hit = (Object.entries(NAV_PATHS) as [NavKey, string][])
    .filter(([, path]) => pathname === path || pathname.startsWith(`${path}/`))
    .sort((left, right) => right[1].length - left[1].length)[0];
  return hit ? hit[0] : "users";
}

const PALETTE_LABEL_KEYS: Record<Palette, MessageKey> = {
  default: "app.palette.default",
  graphite: "app.palette.graphite",
  fresh: "app.palette.fresh",
  violet: "app.palette.violet",
  forest: "app.palette.forest",
};

function navLabelKey(nav: NavKey): MessageKey {
  if (nav === "dataScopes") return "nav.dataScopes";
  if (nav === "fieldPerms") return "nav.fieldPerms";
  for (const group of NAV_GROUPS) {
    const hit = group.items.find((item) => item.key === nav);
    if (hit) return hit.labelKey;
  }
  return "nav.users";
}

/* ------------------------------------------------------------------ */
/* Shell                                                               */
/* ------------------------------------------------------------------ */

export function AdminShell({ children }: { children: ReactNode }) {
  const { t, locale, setLocale } = useI18n();
  const { resolvedTheme, setTheme, palette, palettes, setPalette } = useTheme();
  const { session, logout } = useAuth();
  const { data: effectiveMenus = [] } = useEffectiveMenus();
  const [logoutOpen, setLogoutOpen] = useState(false);
  const [commandOpen, setCommandOpen] = useState(false);
  const router = useRouter();
  const location = useRouterState({ select: (state) => state.location });
  const isNavigating = useRouterState({ select: (state) => state.isLoading });
  const pathname = location.pathname;
  const nav = useMemo(() => navKeyFromPath(pathname), [pathname]);
  const canSearchUsers = effectiveMenus.some(
    (menu) => menu.route === NAV_PATHS.users,
  );
  const canSearchDepartments = effectiveMenus.some(
    (menu) => menu.route === NAV_PATHS.departments,
  );
  const { data: commandUsers = [] } = useUsers(commandOpen && canSearchUsers);
  const { data: commandDepartments = [] } = useDepartments(
    commandOpen && canSearchDepartments,
  );
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key.toLowerCase() === "k" && (event.metaKey || event.ctrlKey)) {
        event.preventDefault();
        setCommandOpen((open) => !open);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const runtimeNavigation = useMemo(() => {
    const visible = effectiveMenus.filter(
      (menu) =>
        !menu.route ||
        (!isDevelopmentPath(menu.route) && isRegisteredMenuPath(menu.route)),
    );
    const byParent = new Map<string, typeof visible>();
    for (const menu of visible) {
      const siblings = byParent.get(menu.parent_id ?? "") ?? [];
      siblings.push(menu);
      byParent.set(menu.parent_id ?? "", siblings);
    }
    for (const siblings of byParent.values())
      siblings.sort(
        (left, right) =>
          left.sort_order - right.sort_order ||
          left.key.localeCompare(right.key),
      );
    const grouped = new Set<string>();
    const descendants = (parentID: string, depth = 0) => {
      const items: Array<(typeof visible)[number] & { depth: number }> = [];
      for (const menu of byParent.get(parentID) ?? []) {
        grouped.add(menu.id);
        if (menu.route) items.push({ ...menu, depth });
        items.push(...descendants(menu.id, menu.route ? depth + 1 : depth));
      }
      return items;
    };
    const groups = (byParent.get("") ?? [])
      .filter((menu) => !menu.route)
      .map((group) => ({
        id: group.id,
        key: group.key,
        label: group.label,
        items: descendants(group.id),
      }))
      .filter((group) => group.items.length > 0);
    const ungrouped = visible
      .filter((menu) => Boolean(menu.route) && !grouped.has(menu.id))
      .map((menu) => ({ ...menu, depth: 0 }));
    if (ungrouped.length)
      groups.push({
        id: "runtime",
        key: "__runtime__",
        label: "Runtime",
        items: ungrouped,
      });
    return groups;
  }, [effectiveMenus]);

  const activeMenu = useMemo(
    () =>
      effectiveMenus
        .filter(
          (menu) =>
            menu.route &&
            (pathname === menu.route || pathname.startsWith(`${menu.route}/`)),
        )
        .sort(
          (left, right) =>
            (right.route?.length ?? 0) - (left.route?.length ?? 0),
        )[0],
    [effectiveMenus, pathname],
  );
  const activeGroup = useMemo(() => {
    const byID = new Map(effectiveMenus.map((menu) => [menu.id, menu]));
    let cursor = activeMenu?.parent_id
      ? byID.get(activeMenu.parent_id)
      : undefined;
    while (cursor?.parent_id) cursor = byID.get(cursor.parent_id);
    return cursor;
  }, [activeMenu, effectiveMenus]);
  const runCommand = (route: string) => {
    setCommandOpen(false);
    void router.navigate({ to: route });
  };

  const iconForRoute = (route: string) => {
    const key = (Object.entries(NAV_PATHS) as [NavKey, string][]).find(
      ([, path]) => path === route,
    )?.[0];
    if (key) {
      for (const group of NAV_GROUPS) {
        const item = group.items.find((candidate) => candidate.key === key);
        if (item) return item.icon;
      }
    }
    return BriefcaseBusiness;
  };

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" className="pointer-events-none">
                <span
                  className="flex size-8 shrink-0 items-center justify-center rounded-lg text-white"
                  style={{ background: "var(--gradient-brand)" }}
                >
                  <ProductBrandMark className="size-4" />
                </span>
                <span className="flex flex-col leading-tight">
                  <span className="font-display text-sm font-extrabold tracking-tight">
                    {PRODUCT_BRAND.consoleTitle}
                  </span>
                  <span className="text-xs text-muted-foreground">
                    {t("shell.product")}
                  </span>
                </span>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          {runtimeNavigation.map((group) => (
            <SidebarGroup key={group.id}>
              <SidebarGroupLabel>
                {systemMenuLabel(t, group.key, group.label)}
              </SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map((item) => {
                    const Icon = iconForRoute(item.route!);
                    const label = systemMenuLabel(t, item.key, item.label);
                    return (
                      <SidebarMenuItem key={item.id}>
                        <SidebarMenuButton
                          asChild
                          isActive={activeMenu?.id === item.id}
                          tooltip={label}
                          style={{
                            paddingInlineStart: item.depth
                              ? `${item.depth * 1.25 + 0.5}rem`
                              : undefined,
                          }}
                        >
                          <Link to={item.route!}>
                            <Icon className="size-4" />
                            <span>{label}</span>
                          </Link>
                        </SidebarMenuButton>
                      </SidebarMenuItem>
                    );
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </SidebarContent>
        <SidebarRail />
      </Sidebar>

      <SidebarInset className="min-w-0">
        <div
          aria-hidden="true"
          data-testid="navigation-progress"
          data-state={isNavigating ? "loading" : "idle"}
          className={cn(
            "pointer-events-none fixed inset-x-0 top-0 z-50 h-0.5 origin-left bg-primary transition-[transform,opacity] duration-300",
            isNavigating ? "scale-x-75 opacity-100" : "scale-x-100 opacity-0",
          )}
        />
        <header className="sticky top-0 z-10 flex h-14 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur">
          <SidebarTrigger aria-label={t("shell.toggleSidebar")} />
          <Separator orientation="vertical" className="mx-1 h-4" />
          <Breadcrumb className="min-w-0">
            <BreadcrumbList>
              {activeGroup ? (
                <>
                  <BreadcrumbItem className="hidden md:block">
                    {systemMenuLabel(t, activeGroup.key, activeGroup.label)}
                  </BreadcrumbItem>
                  <BreadcrumbSeparator className="hidden md:block" />
                </>
              ) : null}
              <BreadcrumbItem>
                <BreadcrumbPage>
                  {activeMenu
                    ? systemMenuLabel(t, activeMenu.key, activeMenu.label)
                    : t(navLabelKey(nav))}
                </BreadcrumbPage>
              </BreadcrumbItem>
            </BreadcrumbList>
          </Breadcrumb>
          <div className="ml-auto flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="hidden min-w-40 justify-between gap-3 text-muted-foreground lg:flex"
              onClick={() => setCommandOpen(true)}
            >
              <span className="inline-flex items-center gap-2">
                <Search className="size-4" />
                {t("command.open")}
              </span>
              <kbd className="rounded border bg-muted px-1.5 py-0.5 text-[10px]">
                ⌘K
              </kbd>
            </Button>
            <Select
              value={locale}
              onValueChange={(value) => setLocale(value as Locale)}
            >
              <SelectTrigger
                size="sm"
                className="w-28"
                data-testid="locale-select"
              >
                <Languages className="size-4 text-muted-foreground" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {LOCALES.map((item) => (
                  <SelectItem key={item.value} value={item.value}>
                    {item.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select
              value={palette}
              onValueChange={(value) => setPalette(value as Palette)}
            >
              <SelectTrigger size="sm" className="hidden w-40 lg:flex">
                <PaletteIcon className="size-4 text-muted-foreground" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {palettes.map((item) => (
                  <SelectItem key={item} value={item}>
                    {t(PALETTE_LABEL_KEYS[item])}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              variant="outline"
              size="icon"
              aria-label={t("app.themeToggleAria")}
              onClick={() =>
                setTheme(resolvedTheme === "dark" ? "light" : "dark")
              }
            >
              {resolvedTheme === "dark" ? <Sun /> : <Moon />}
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button
                  aria-label={t("shell.userMenu")}
                  className="rounded-full"
                >
                  <Avatar className="size-8">
                    <AvatarFallback
                      className="text-xs font-bold text-white"
                      style={{ background: "var(--gradient-brand)" }}
                    >
                      {(session?.displayName ?? "A").slice(0, 1).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" className="w-44">
                <DropdownMenuLabel className="flex items-center gap-2">
                  <UserIcon className="size-4 text-muted-foreground" />
                  <span className="truncate">{session?.username}</span>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  onSelect={() => setLogoutOpen(true)}
                >
                  <LogOut className="size-4" />
                  {t("shell.logout")}
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </header>
        {session ? (
          <PendingSystemDrafts />
        ) : null}
        <div
          key={pathname}
          className="min-w-0 flex-1 animate-in fade-in duration-200"
        >
          <PageErrorBoundary key={location.href} resetKey={location.href}>
            <ShellPageContent
              errorProbe={location.searchStr.includes(
                "__error_boundary_probe=1",
              )}
            >
              {children}
            </ShellPageContent>
          </PageErrorBoundary>
        </div>
      </SidebarInset>
      <AlertDialog open={logoutOpen} onOpenChange={setLogoutOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("shell.logoutConfirmTitle")}</AlertDialogTitle>
            <AlertDialogDescription>
              {t("shell.logoutConfirmDesc")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction onClick={() => void logout()}>
              {t("shell.logoutConfirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
      <CommandDialog
        open={commandOpen}
        onOpenChange={setCommandOpen}
        title={t("command.title")}
        description={t("command.description")}
      >
        <CommandInput placeholder={t("command.placeholder")} />
        <CommandList>
          <CommandEmpty>{t("command.empty")}</CommandEmpty>
          <CommandGroup heading={t("command.pages")}>
            {effectiveMenus
              .filter(
                (menu) =>
                  Boolean(menu.route) && !isDevelopmentPath(menu.route!),
              )
              .map((menu) => {
                const Icon = iconForRoute(menu.route!);
                const label = systemMenuLabel(t, menu.key, menu.label);
                const navKey = (
                  Object.entries(NAV_PATHS) as [NavKey, string][]
                ).find(([, path]) => path === menu.route)?.[0];
                return (
                  <CommandItem
                    key={menu.id}
                    value={`${label} ${menu.label} ${menu.route} ${navKey ? t(navLabelKey(navKey)) : ""}`}
                    onSelect={() => runCommand(menu.route!)}
                  >
                    <Icon />
                    <span>{label}</span>
                    <CommandShortcut>{menu.route}</CommandShortcut>
                  </CommandItem>
                );
              })}
          </CommandGroup>
          {canSearchUsers && commandUsers.length ? (
            <CommandGroup heading={t("command.people")}>
              {commandUsers.map((user) => {
                const name = displayText(t, user.name);
                return (
                  <CommandItem
                    key={user.id}
                    value={`${name} ${user.email} ${t("command.people")}`}
                    onSelect={() => runCommand(NAV_PATHS.users)}
                  >
                    <UserIcon />
                    <span>{name}</span>
                    <CommandShortcut>{user.email}</CommandShortcut>
                  </CommandItem>
                );
              })}
            </CommandGroup>
          ) : null}
          {canSearchDepartments && commandDepartments.length ? (
            <CommandGroup heading={t("command.departments")}>
              {commandDepartments.map((department) => (
                <CommandItem
                  key={department.id}
                  value={`${displayText(t, department.name)} ${t("command.departments")}`}
                  onSelect={() => runCommand(NAV_PATHS.departments)}
                >
                  <Building2 />
                  <span>{displayText(t, department.name)}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          ) : null}
        </CommandList>
      </CommandDialog>
    </SidebarProvider>
  );
}

function ShellPageContent({
  children,
  errorProbe,
}: {
  children: ReactNode;
  errorProbe: boolean;
}) {
  if (import.meta.env.DEV && errorProbe) {
    throw new Error("Phase 2.5 error boundary probe");
  }
  return children;
}
