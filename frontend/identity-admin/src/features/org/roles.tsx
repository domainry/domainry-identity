import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { zodResolver } from '@hookform/resolvers/zod'
import { useForm } from 'react-hook-form'
import type { ColumnDef } from '@tanstack/react-table'
import { ChevronRight, Plus, Search, ShieldCheck } from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Checkbox,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Skeleton,
  Separator,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
} from '@domainry/ui'
import { DataTable, type DataTableSearch } from '@/components/data-table'
import { PageShell } from '@/components/page-shell'
import { StatusBadge } from '@/components/status-badge'
import { TableColumnHeader } from '@domainry/ui/components/kibo-ui/table'
import { cn } from '@/lib/utils'
import { useI18n } from '@/lib/i18n'
import { displayText } from '@/data/text'
import { useCreateRole, useRolePage } from '@/data/hooks'
import { identityPoliciesApi, menusApi, objectsApi, permissionsApi, type RoleCreateInput, type RuntimeDataScope } from '@/data/api'
import type { IdentityRolePermissionGrant } from '@/data/governance-api'
import type { Role } from '@/data/types'
import { runtimeApiError } from '@/lib/runtime-api'
import { runtimeErrorConstraintMessage } from '@/lib/runtime-error-details'
import { roleFormControl } from './identity-form-error'
import {
  buildRoleMenuTree,
  filterRoleMenuTree,
  roleMenuCheckState,
  toggleRoleMenuSelection,
  type RoleMenuTreeNode,
} from './role-menu-selection'
import { FieldPermissionsPage } from './field-permissions'
import { EffectiveAccessWorkspace } from './effective-access-workspace'
import { RoleGovernanceDetail } from './role-governance-detail'
import { buildPermissionCatalogView, type PermissionCatalogGroupView } from './permission-capability-view'

interface RoleMenuRowProps {
  node: RoleMenuTreeNode
  selectedIDs: Set<string>
  disabled: boolean
  forceExpanded?: boolean
  depth?: number
  onToggle: (menuID: string, checked: boolean) => void
  t: ReturnType<typeof useI18n>['t']
}

function RoleMenuRow({ node, selectedIDs, disabled, forceExpanded = false, depth = 0, onToggle, t }: RoleMenuRowProps) {
  const state = roleMenuCheckState(node, selectedIDs)
  const [expanded, setExpanded] = useState(false)
  const hasChildren = node.children.length > 0
  const isExpanded = forceExpanded || expanded
  return (
    <>
      <div className='flex min-h-11 items-center gap-2 border-b px-3 py-2 last:border-b-0 hover:bg-muted/40' style={{ paddingInlineStart: `${12 + depth * 20}px` }}>
        {hasChildren ? (
          <Button
            type='button'
            variant='ghost'
            size='icon-xs'
            aria-label={t(isExpanded ? 'tree.collapse' : 'tree.expand', { name: displayText(t, node.name) })}
            aria-expanded={isExpanded}
            onClick={() => setExpanded((current) => !current)}
          >
            <ChevronRight className={cn('transition-transform', isExpanded && 'rotate-90')} />
          </Button>
        ) : <span className='size-6 shrink-0' aria-hidden='true' />}
        <Checkbox
          aria-label={t('roles.menus.toggle', { name: displayText(t, node.name) })}
          checked={state}
          disabled={disabled}
          onCheckedChange={(checked) => onToggle(node.id, checked === true)}
        />
        <span className='min-w-0 flex-1 truncate text-sm font-medium'>{displayText(t, node.name)}</span>
        {!node.visible ? <span className='text-xs text-muted-foreground'>{t('common.disabled')}</span> : null}
      </div>
      {hasChildren && isExpanded
        ? node.children.map((child) => <RoleMenuRow key={child.id} node={child} selectedIDs={selectedIDs} disabled={disabled} forceExpanded={forceExpanded} depth={depth + 1} onToggle={onToggle} t={t} />)
        : null}
    </>
  )
}

export function RolesPage() {
  const { t } = useI18n()
  return (
    <Tabs defaultValue='role-policy' aria-label={t('roles.governanceTabs.label')}>
      <TabsList>
        <TabsTrigger value='role-policy'>{t('roles.governanceTabs.rolePolicy')}</TabsTrigger>
        <TabsTrigger value='field-permissions'>{t('roles.governanceTabs.fieldPermissions')}</TabsTrigger>
        <TabsTrigger value='effective-access'>{t('roles.governanceTabs.effectiveAccess')}</TabsTrigger>
      </TabsList>
      <TabsContent value='role-policy'>
        <RolePolicyWorkspace />
      </TabsContent>
      <TabsContent value='field-permissions'>
        <FieldPermissionsPage />
      </TabsContent>
      <TabsContent value='effective-access'>
        <EffectiveAccessWorkspace />
      </TabsContent>
    </Tabs>
  )
}

const ROLE_DATA_SCOPES: RuntimeDataScope[] = ['all', 'owner', 'org', 'org_child', 'target_org']

function roleDataScopeLabel(scope: RuntimeDataScope, t: ReturnType<typeof useI18n>['t']) {
  switch (scope) {
    case 'all': return t('scopes.type.all')
    case 'owner': return t('scopes.type.self')
    case 'org': return t('scopes.type.organization')
    case 'org_child': return t('scopes.type.organizationTree')
    case 'target_org': return t('scopes.type.targetOrganization')
  }
}

interface PermissionChecklistProps {
  groups: PermissionCatalogGroupView[]
  grants: IdentityRolePermissionGrant[]
  query: string
  disabled?: boolean
  controlPrefix?: string
  onToggle: (permissionKey: string, checked: boolean) => void
  onScopeChange: (permissionKey: string, scope: RuntimeDataScope) => void
  t: ReturnType<typeof useI18n>['t']
}

function PermissionChecklist({ groups, grants, query, disabled = false, controlPrefix, onToggle, onScopeChange, t }: PermissionChecklistProps) {
  const [expandedGroupKeys, setExpandedGroupKeys] = useState<Set<string>>(new Set())
  const grantByKey = useMemo(() => new Map(grants.map((grant) => [grant.permission_key, grant])), [grants])
  const searching = Boolean(query.trim())
  const filteredGroups = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase()
    if (!normalizedQuery) return groups
    return groups.flatMap((group) => {
      const moduleMatches = `${group.resourceLabel} ${group.resourceKey} ${group.category}`.toLowerCase().includes(normalizedQuery)
      const permissions = moduleMatches
        ? group.permissions
        : group.permissions.filter((permission) => `${permission.label} ${permission.key}`.toLowerCase().includes(normalizedQuery))
      return permissions.length ? [{ ...group, permissions }] : []
    })
  }, [groups, query])

  if (!filteredGroups.length) {
    return <p className='rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground'>{query.trim() ? t('roles.permissions.noResults') : t('roles.capabilities.empty')}</p>
  }

  return (
    <div className='divide-y overflow-hidden rounded-md border'>
      {filteredGroups.map((group) => {
        const selectedCount = group.permissions.filter((permission) => grantByKey.has(permission.key)).length
        return (
        <details
          key={group.key}
          open={searching || expandedGroupKeys.has(group.key)}
          onToggle={(event) => {
            if (searching) return
            const open = event.currentTarget.open
            setExpandedGroupKeys((current) => {
              const next = new Set(current)
              if (open) next.add(group.key)
              else next.delete(group.key)
              return next
            })
          }}
          className='group/module min-w-0'
        >
          <summary className='grid min-h-11 cursor-pointer list-none grid-cols-[1.5rem_minmax(0,1fr)_auto] items-center gap-2 bg-muted/35 px-3 py-2.5 outline-none hover:bg-muted/55 focus-visible:ring-2 focus-visible:ring-ring/50 [&::-webkit-details-marker]:hidden'>
            <ChevronRight className='size-4 text-muted-foreground transition-transform group-open/module:rotate-90' />
            <span className='min-w-0 truncate text-sm font-semibold'>{group.resourceLabel}</span>
            <span className='text-xs text-muted-foreground'>{t('roles.permissions.moduleCount', { selected: selectedCount, total: group.permissions.length })}</span>
          </summary>
          <div className='grid grid-cols-[2rem_minmax(0,1fr)_11.5rem] items-center gap-2 border-t bg-muted/10 px-3 py-2 text-xs font-medium text-muted-foreground max-sm:hidden'>
            <span />
            <span>{t('roles.permissions.permission')}</span>
            <span>{t('scopes.table.scope')}</span>
          </div>
          <div className='divide-y'>
            {group.permissions.map((permission) => {
              const grant = grantByKey.get(permission.key)
              const available = permission.active && permission.enabled
              const toggleDisabled = disabled || (!available && !grant)
              return (
                <div key={permission.key} className='grid min-h-12 grid-cols-[2rem_minmax(0,1fr)] items-center gap-x-2 gap-y-2 px-3 py-2.5 hover:bg-muted/20 sm:grid-cols-[2rem_minmax(0,1fr)_11.5rem]'>
                  <Checkbox
                    aria-label={permission.label}
                    checked={Boolean(grant)}
                    disabled={toggleDisabled}
                    onCheckedChange={(checked) => onToggle(permission.key, checked === true)}
                  />
                  <div className='min-w-0'>
                    <p className='break-all text-sm font-medium leading-5'>{permission.label}</p>
                    {!available ? <p className='text-xs text-muted-foreground'>{permission.active ? t('roles.capabilities.disabled') : t('roles.capabilities.retired')}</p> : null}
                  </div>
                  <Select value={grant?.data_scope ?? ''} disabled={disabled || !grant || !available} onValueChange={(scope) => onScopeChange(permission.key, scope as RuntimeDataScope)}>
                    <SelectTrigger size='sm' className='col-start-2 w-full sm:col-start-3 sm:row-start-1' aria-label={`${permission.label} ${t('scopes.table.scope')}`} data-policy-control={`${controlPrefix ? `${controlPrefix}:` : ''}${permission.key}:data_scope`}>
                      <SelectValue placeholder={t('scopes.type.none')} />
                    </SelectTrigger>
                    <SelectContent><SelectGroup>{ROLE_DATA_SCOPES.map((scope) => <SelectItem key={scope} value={scope}>{roleDataScopeLabel(scope, t)}</SelectItem>)}</SelectGroup></SelectContent>
                  </Select>
                </div>
              )
            })}
          </div>
        </details>
      )})}
    </div>
  )
}

function RolePolicyWorkspace() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [listQuery, setListQuery] = useState({ page: 1, pageSize: 10, search: '' })
  const rolesQuery = useRolePage({ ...listQuery, searchFields: ['label', 'key'] })
  const roles = rolesQuery.data?.items ?? []
  const roleTotal = rolesQuery.data?.total ?? 0
  const createRoleMut = useCreateRole()
  const [selectedId, setSelectedId] = useState('r1')
  const [draftPermissions, setDraftPermissions] = useState<IdentityRolePermissionGrant[]>([])
  const [permsDirty, setPermsDirty] = useState(false)
  const [permissionChangeReason, setPermissionChangeReason] = useState('')
  const [permissionSearch, setPermissionSearch] = useState('')
  const [permissionPublishOpen, setPermissionPublishOpen] = useState(false)
  const [activePolicyTab, setActivePolicyTab] = useState<'overview' | 'permissions' | 'menus'>('permissions')
  const [draftMenuIDs, setDraftMenuIDs] = useState<string[]>([])
  const [menusDirty, setMenusDirty] = useState(false)
  const [menuSearch, setMenuSearch] = useState('')
  const [pendingSelectedId, setPendingSelectedId] = useState<string | null>(null)
  const [policyDiscardOpen, setPolicyDiscardOpen] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [discardOpen, setDiscardOpen] = useState(false)
  const [createPermissions, setCreatePermissions] = useState<IdentityRolePermissionGrant[]>([])
  const [createPermissionSearch, setCreatePermissionSearch] = useState('')
  const permissionCatalogQuery = useQuery({ queryKey: ['runtime', 'identity', 'permission-catalog'], queryFn: permissionsApi.catalog })
  const schemaQuery = useQuery({ queryKey: ['runtime', 'schema', 'role-create'], queryFn: objectsApi.schemaSnapshot })
  const roleSearch = useMemo<DataTableSearch>(() => ({
    fields: ['label', 'key'],
    value: listQuery.search,
    placeholder: t('roles.searchPlaceholder'),
    onChange: (search) => setListQuery((current) => ({ ...current, page: 1, search })),
  }), [listQuery.search, t])
  const roleSchema = useMemo(() => z.object({
    name: z.string().trim().min(1, t('roles.validation.nameRequired')),
    code: z.string().trim().min(1, t('roles.validation.codeRequired')).regex(/^[A-Za-z][A-Za-z0-9_]*$/, t('roles.validation.codeFormat')),
    description: z.string(),
    businessReason: z.string().trim().min(1, t('roles.permissionPublication.reasonRequired')),
  }).superRefine((values, context) => {
    if (roles.some((role) => role.code.toLowerCase() === values.code.trim().toLowerCase())) {
      context.addIssue({ code: 'custom', path: ['code'], message: t('roles.validation.codeUnique') })
    }
  }), [roles, t])
  type RoleFormValues = z.input<typeof roleSchema>
  const { register, reset, handleSubmit, setError, formState: { errors, isDirty } } = useForm<RoleFormValues>({ resolver: zodResolver(roleSchema), defaultValues: { name: '', code: '', description: '', businessReason: '' }, mode: 'onBlur' })

  const selected = useMemo<Role | undefined>(
    () => roles.find((r) => r.id === selectedId) ?? roles[0],
    [roles, selectedId]
  )
  const rolePermissionsQuery = useQuery({
    queryKey: ['runtime', 'identity', 'role-permissions', selected?.id],
    queryFn: () => identityPoliciesApi.rolePermissionConfiguration(selected!.id),
    enabled: Boolean(selected?.id),
  })
  const menusQuery = useQuery({ queryKey: ['runtime', 'identity', 'menus'], queryFn: menusApi.list })
  const roleMenusQuery = useQuery({
    queryKey: ['runtime', 'identity', 'role-menus', selected?.id],
    queryFn: () => identityPoliciesApi.roleMenus(selected!.id),
    enabled: Boolean(selected?.id),
  })
  const savePermissions = useMutation({
    mutationFn: async () => {
      if (!selected) throw new Error('role-not-ready')
      if (!permissionChangeReason.trim()) throw new Error('reason-required')
      if (!rolePermissionsQuery.data?.schemaHash) throw new Error('role-permission-revision-not-ready')
      return identityPoliciesApi.saveRolePermissions(selected.id, draftPermissions, permissionChangeReason.trim(), rolePermissionsQuery.data.schemaHash)
    },
    onSuccess: async (configuration) => {
      queryClient.setQueryData(['runtime', 'identity', 'role-permissions', selected?.id], configuration)
      setDraftPermissions(configuration.permissions)
      setPermsDirty(false)
      setPermissionChangeReason('')
      setPermissionPublishOpen(false)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['runtime', 'identity', 'role-permissions', selected?.id] }),
        queryClient.invalidateQueries({ queryKey: ['runtime', 'identity', 'roles'] }),
        queryClient.invalidateQueries({ queryKey: ['runtime', 'permissions', 'effective'] }),
      ])
      toast.success(t('roles.permissionPublication.toast.published'))
    },
    onError: (error) => toast.error(error instanceof Error && error.message === 'reason-required' ? t('roles.permissionPublication.reasonRequired') : t('roles.permissionPublication.toast.failed')),
  })
  const saveMenus = useMutation({
    mutationFn: () => identityPoliciesApi.saveRoleMenus(selected!.id, draftMenuIDs),
    onSuccess: async (assignments) => {
      setDraftMenuIDs(assignments.map((assignment) => assignment.menu_id).sort())
      setMenusDirty(false)
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['runtime', 'identity', 'role-menus', selected?.id] }),
        queryClient.invalidateQueries({ queryKey: ['runtime', 'identity', 'effective-menus'] }),
      ])
      toast.success(t('roles.menus.toast.saved', { name: selected ? displayText(t, selected.name) : '' }))
    },
    onError: () => toast.error(t('roles.menus.toast.failed')),
  })
	const runtimeResourceLabels = useMemo(() => new Map((schemaQuery.data?.objects ?? []).map((object) => [object.key, object.name || object.label || object.key])), [schemaQuery.data?.objects])
	const permissionCatalogGroups = useMemo(() => buildPermissionCatalogView(permissionCatalogQuery.data ?? [], runtimeResourceLabels), [permissionCatalogQuery.data, runtimeResourceLabels])
  const menuTree = useMemo(() => buildRoleMenuTree(menusQuery.data ?? []), [menusQuery.data])
  const filteredMenuTree = useMemo(
    () => filterRoleMenuTree(menuTree, menuSearch, (node) => displayText(t, node.name)),
    [menuSearch, menuTree, t],
  )
  const selectedMenuIDs = useMemo(() => new Set(draftMenuIDs), [draftMenuIDs])
  useEffect(() => {
    setPermsDirty(false)
    setPermissionChangeReason('')
    setPermissionSearch('')
    setPermissionPublishOpen(false)
    setMenusDirty(false)
    setMenuSearch('')
  }, [selected?.id])
  useEffect(() => {
    if (permsDirty || !rolePermissionsQuery.data) return
    setDraftPermissions(rolePermissionsQuery.data.permissions)
  }, [permsDirty, rolePermissionsQuery.data, selected?.code])
  useEffect(() => {
    if (menusDirty || !roleMenusQuery.data) return
    setDraftMenuIDs(roleMenusQuery.data)
  }, [menusDirty, roleMenusQuery.data])
  const roleColumns = useMemo<ColumnDef<Role>[]>(() => [
    {
      id: 'name',
      accessorFn: (role) => displayText(t, role.name),
      header: ({ column }) => <TableColumnHeader column={column} title={t('roles.form.name')} />,
      cell: ({ row }) => {
        const role = row.original
		return <button className={cn('flex w-full items-center gap-2 rounded-md p-1 text-left', role.id === selected?.id && 'bg-accent')} onClick={() => requestRoleSelection(role.id)}><ShieldCheck className='size-4 shrink-0 text-muted-foreground' /><span className='min-w-0'><span className='truncate font-medium'>{displayText(t, role.name)}</span><span className='block truncate text-xs text-muted-foreground'>{displayText(t, role.description) || t('roles.noDescription')}</span></span></button>
      },
    },
    { accessorKey: 'code', header: ({ column }) => <TableColumnHeader column={column} title={t('roles.form.code')} />, cell: ({ row }) => <code className='text-xs'>{row.original.code}</code> },
    { accessorKey: 'members', header: ({ column }) => <TableColumnHeader column={column} title={t('roles.list.title')} />, cell: ({ row }) => t('roles.memberCount', { count: row.original.members }) },
    { accessorKey: 'status', header: ({ column }) => <TableColumnHeader column={column} title={t('common.status')} />, cell: ({ row }) => <StatusBadge value={row.original.status}>{row.original.status === 'active' ? t('common.enabled') : t('common.disabled')}</StatusBadge> },
  ], [menusDirty, permsDirty, selected?.id, t])

  function togglePermission(permissionKey: string, checked: boolean) {
    if (!selected) return
    const next = new Map(draftPermissions.map((permission) => [permission.permission_key, permission]))
    if (checked) next.set(permissionKey, next.get(permissionKey) ?? { permission_key: permissionKey, data_scope: 'all' })
    else next.delete(permissionKey)
    setDraftPermissions([...next.values()].sort((left, right) => left.permission_key.localeCompare(right.permission_key)))
    setPermsDirty(true)
  }

  function setPermissionScope(permissionKey: string, dataScope: RuntimeDataScope) {
    setDraftPermissions((current) => current.map((permission) => permission.permission_key === permissionKey ? { ...permission, data_scope: dataScope } : permission))
    setPermsDirty(true)
  }

  function requestRoleSelection(roleID: string) {
    if (roleID === selected?.id) return
    if (permsDirty || menusDirty) {
      setPendingSelectedId(roleID)
      setPolicyDiscardOpen(true)
      return
    }
    setSelectedId(roleID)
  }

  function toggleMenu(menuID: string, checked: boolean) {
    if (!selected) return
    setDraftMenuIDs(toggleRoleMenuSelection(menusQuery.data ?? [], draftMenuIDs, menuID, checked))
    setMenusDirty(true)
  }

  function openCreateRole() {
    reset({ name: '', code: '', description: '', businessReason: '' })
    setCreatePermissions([])
    setCreatePermissionSearch('')
    setCreateOpen(true)
  }

  function requestCreateOpen(open: boolean) {
    if (!open && isDirty) setDiscardOpen(true)
    else setCreateOpen(open)
  }

  async function createRole(values: RoleFormValues) {
    const input: RoleCreateInput = {
      name: values.name.trim(),
      code: values.code.trim().toUpperCase(),
      description: values.description.trim(),
      members: 0,
      status: 'active',
      businessReason: values.businessReason.trim(),
      permissions: createPermissions,
    }
    try {
      await createRoleMut.mutateAsync(input)
      toast.success(t('roles.create.toast.created'))
      setCreateOpen(false)
      reset({ name: '', code: '', description: '', businessReason: '' })
      setCreatePermissions([])
    } catch (error) {
      const structured = runtimeApiError(error)
      setError(roleFormControl(structured) ?? 'root', { message: runtimeErrorConstraintMessage(t, structured, error instanceof Error ? error.message : t('dataTable.errorDescription')) })
    }
  }

  if (!selected) {
    return (
      <PageShell title={t('roles.title')} description={t('roles.desc')}>
        <DataTable columns={roleColumns} data={roles} columnLabels={{ name: t('roles.form.name'), code: t('roles.form.code'), members: t('roles.list.title'), status: t('common.status') }} search={roleSearch} manualPagination={{ page: listQuery.page, pageSize: listQuery.pageSize, total: roleTotal, onChange: (page, pageSize) => setListQuery((current) => ({ ...current, page, pageSize })) }} isLoading={rolesQuery.isLoading} isRefreshing={rolesQuery.isFetching && !rolesQuery.isLoading} error={rolesQuery.error} onRetry={() => void rolesQuery.refetch()} />
      </PageShell>
    )
  }
  if (permissionCatalogQuery.isError || rolePermissionsQuery.isError) {
    return <PageShell title={t('roles.title')} description={t('roles.desc')}><p role='alert' className='text-sm text-destructive'>{t('dataTable.errorDescription')}</p></PageShell>
  }

  const rolePublicationBusy = savePermissions.isPending

  return (
    <PageShell
      title={t('roles.title')}
      description={t('roles.desc')}
      actions={
        <Button onClick={openCreateRole}>
          <Plus data-icon='inline-start' />
          {t('roles.new')}
        </Button>
      }
    >
      <div className='grid min-w-0 gap-4 xl:grid-cols-[minmax(360px,0.8fr)_minmax(0,1.2fr)]'>
        <Card className='h-fit min-w-0'>
          <CardHeader className='pb-2'>
            <CardTitle className='text-sm'>{t('roles.list.title')}</CardTitle>
          </CardHeader>
          <CardContent><DataTable columns={roleColumns} data={roles} getRowId={(role) => role.id} columnLabels={{ name: t('roles.form.name'), code: t('roles.form.code'), members: t('roles.list.title'), status: t('common.status') }} search={roleSearch} manualPagination={{ page: listQuery.page, pageSize: listQuery.pageSize, total: roleTotal, onChange: (page, pageSize) => setListQuery((current) => ({ ...current, page, pageSize })) }} isLoading={rolesQuery.isLoading} isRefreshing={rolesQuery.isFetching && !rolesQuery.isLoading} error={rolesQuery.error} onRetry={() => void rolesQuery.refetch()} pageSizeOptions={[10, 20]} /></CardContent>
        </Card>

        <Card className='min-w-0'>
          <CardHeader>
            <div className='flex flex-wrap items-start justify-between gap-3'>
              <div>
                <CardTitle className='flex items-center gap-2 text-base'>
                  {displayText(t, selected.name)}
                  <StatusBadge value={selected.status}>
                    {selected.status === 'active' ? t('common.enabled') : t('common.disabled')}
                  </StatusBadge>
                </CardTitle>
                <CardDescription className='mt-1'>
                  {selected.description
                    ? displayText(t, selected.description)
                    : t('roles.noDescription')}
                </CardDescription>
              </div>
              {activePolicyTab === 'permissions' ? <div className='flex flex-wrap gap-2'>
					<Button size='sm' disabled={!permsDirty || rolePublicationBusy} onClick={() => setPermissionPublishOpen(true)}>{t('roles.permissionPublication.publish')}</Button>
				  </div> : activePolicyTab === 'menus' ? <Button size='sm' disabled={!menusDirty || saveMenus.isPending} onClick={() => saveMenus.mutate()}>{menusDirty ? t('roles.menus.saveDirty') : t('roles.menus.save')}</Button> : null}
            </div>
          </CardHeader>
          <Separator />
          <CardContent className='pt-4'>
            <Tabs value={activePolicyTab} onValueChange={(value) => setActivePolicyTab(value as 'overview' | 'permissions' | 'menus')}>
              <TabsList aria-label={t('roles.policyTabs.label')}>
                <TabsTrigger value='overview'>{t('roles.policyTabs.overview')}</TabsTrigger>
                <TabsTrigger value='permissions'>{t('roles.policyTabs.permissions')}</TabsTrigger>
                <TabsTrigger value='menus'>{t('roles.policyTabs.menus')}</TabsTrigger>
              </TabsList>
              <TabsContent value='overview' className='mt-3'>
                <RoleGovernanceDetail roleID={selected.id} />
              </TabsContent>
              <TabsContent value='permissions' className='mt-3'>
                <div className='mb-3 flex flex-wrap items-center gap-2'>
                  <div className='relative min-w-[220px] flex-1'>
                    <Search className='pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground' />
                    <Input value={permissionSearch} onChange={(event) => setPermissionSearch(event.target.value)} placeholder={t('roles.permissions.search')} className='pl-9' />
                  </div>
                  <span className='text-xs text-muted-foreground'>{t('roles.permissions.selectedCount', { count: draftPermissions.length })}</span>
                </div>
                <PermissionChecklist groups={permissionCatalogGroups} grants={draftPermissions} query={permissionSearch} disabled={rolePermissionsQuery.isPending || rolePublicationBusy} controlPrefix={selected.id} onToggle={togglePermission} onScopeChange={setPermissionScope} t={t} />
                {draftPermissions.some((permission) => permission.data_scope === 'target_org') ? (
                  <p className='mt-3 text-xs leading-5 text-muted-foreground'>
                    {t('roles.permissions.targetOrgNotice')}{' '}
                    <Link to='/admin/security/accounts' className='font-medium text-foreground underline underline-offset-4'>{t('roles.permissions.configureAccounts')}</Link>
                  </p>
                ) : null}
              </TabsContent>
              <TabsContent value='menus' className='mt-3'>
                <div className='mb-3 flex flex-wrap items-center gap-2'>
                  <div className='relative min-w-[220px] flex-1'>
                    <Search className='pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground' />
                    <Input value={menuSearch} onChange={(event) => setMenuSearch(event.target.value)} placeholder={t('roles.menus.search')} className='pl-9' />
                  </div>
                  <Badge variant='secondary'>{t('roles.menus.selectedCount', { count: draftMenuIDs.length })}</Badge>
				  <Button variant='outline' size='sm' disabled={draftMenuIDs.length === 0} onClick={() => { setDraftMenuIDs([]); setMenusDirty(true) }}>
                    {t('roles.menus.clear')}
                  </Button>
                </div>
                {menusQuery.isPending || roleMenusQuery.isPending ? (
                  <div className='space-y-2 rounded-md border p-3' aria-label={t('roles.menus.loading')}>
                    {[0, 1, 2, 3].map((item) => <Skeleton key={item} className='h-11 w-full' />)}
                  </div>
                ) : menusQuery.isError || roleMenusQuery.isError ? (
                  <div className='rounded-md border border-destructive/30 bg-destructive/5 p-4' role='alert'>
                    <p className='text-sm text-destructive'>{t('roles.menus.loadFailed')}</p>
                    <Button variant='outline' size='sm' className='mt-3' onClick={() => { void menusQuery.refetch(); void roleMenusQuery.refetch() }}>{t('common.retry')}</Button>
                  </div>
                ) : menuTree.length === 0 ? (
                  <div className='rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground'>{t('roles.menus.empty')}</div>
                ) : filteredMenuTree.length === 0 ? (
                  <div className='rounded-md border border-dashed p-8 text-center text-sm text-muted-foreground'>
                    <p>{t('roles.menus.noResults')}</p>
                    <Button variant='link' size='sm' onClick={() => setMenuSearch('')}>{t('roles.menus.clearSearch')}</Button>
                  </div>
                ) : (
                  <div className='max-h-[560px] overflow-y-auto rounded-md border'>
						{filteredMenuTree.map((node) => <RoleMenuRow key={node.id} node={node} selectedIDs={selectedMenuIDs} disabled={saveMenus.isPending} forceExpanded={Boolean(menuSearch.trim())} onToggle={toggleMenu} t={t} />)}
                  </div>
                )}
				<p className='mt-3 text-xs text-muted-foreground'>{t('roles.menus.hint')}</p>
              </TabsContent>
            </Tabs>
          </CardContent>
        </Card>
      </div>

      <Dialog open={createOpen} onOpenChange={requestCreateOpen}>
        <DialogContent className='max-h-[90vh] overflow-y-auto sm:max-w-2xl'>
          <DialogHeader>
            <DialogTitle>{t('roles.new')}</DialogTitle>
            <DialogDescription>{t('roles.dialog.createDesc')}</DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field data-invalid={Boolean(errors.name)}><FieldLabel htmlFor='role-name'>{t('roles.form.name')}</FieldLabel><Input id='role-name' placeholder={t('roles.form.namePlaceholder')} aria-invalid={Boolean(errors.name)} {...register('name')} /><FieldError errors={[errors.name]} /></Field>
            <Field data-invalid={Boolean(errors.code)}><FieldLabel htmlFor='role-code'>{t('roles.form.code')}</FieldLabel><Input id='role-code' placeholder='SALES_LEAD' aria-invalid={Boolean(errors.code)} {...register('code')} /><FieldError errors={[errors.code]} /></Field>
            <Field><FieldLabel htmlFor='role-desc'>{t('roles.form.desc')}</FieldLabel><Textarea id='role-desc' placeholder={t('roles.form.descPlaceholder')} {...register('description')} /></Field>
            <Field data-invalid={Boolean(errors.businessReason)}>
              <FieldLabel htmlFor='role-business-reason'>{t('roles.permissionPublication.reason')}</FieldLabel>
              <Textarea id='role-business-reason' placeholder={t('roles.create.reasonPlaceholder')} aria-invalid={Boolean(errors.businessReason)} {...register('businessReason')} />
              <FieldError errors={[errors.businessReason]} />
            </Field>
            <Field>
              <FieldLabel htmlFor='role-permission-search'>{t('roles.create.permissions')}</FieldLabel>
              <Input id='role-permission-search' value={createPermissionSearch} placeholder={t('roles.create.permissionsSearch')} onChange={(event) => setCreatePermissionSearch(event.target.value)} />
              <div className='max-h-72 overflow-y-auto'>
                <PermissionChecklist
                  groups={permissionCatalogGroups}
                  grants={createPermissions}
                  query={createPermissionSearch}
                  disabled={createRoleMut.isPending}
                  onToggle={(permissionKey, checked) => setCreatePermissions((current) => {
                    const values = new Map(current.map((permission) => [permission.permission_key, permission]))
                    if (checked) values.set(permissionKey, values.get(permissionKey) ?? { permission_key: permissionKey, data_scope: 'all' })
                    else values.delete(permissionKey)
                    return [...values.values()].sort((left, right) => left.permission_key.localeCompare(right.permission_key))
                  })}
                  onScopeChange={(permissionKey, scope) => setCreatePermissions((current) => current.map((permission) => permission.permission_key === permissionKey ? { ...permission, data_scope: scope } : permission))}
                  t={t}
                />
              </div>
              <p className='text-xs text-muted-foreground'>{t('roles.create.permissionsSelected', { count: createPermissions.length })}</p>
              {createPermissions.some((permission) => permission.data_scope === 'target_org') ? <p className='text-xs leading-5 text-muted-foreground'>{t('roles.permissions.targetOrgNotice')}</p> : null}
            </Field>
          </FieldGroup>
          <FieldError errors={[errors.root]} />
          <DialogFooter>
            <Button variant='outline' onClick={() => requestCreateOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button disabled={createRoleMut.isPending} onClick={handleSubmit(createRole)}>{t('common.create')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={permissionPublishOpen} onOpenChange={setPermissionPublishOpen}>
        <DialogContent className='sm:max-w-lg'>
          <DialogHeader>
            <DialogTitle>{t('roles.permissionPublication.title')}</DialogTitle>
            <DialogDescription>{t('roles.permissionPublication.description')}</DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor='role-permission-reason'>{t('roles.permissionPublication.reason')}</FieldLabel>
            <Textarea id='role-permission-reason' value={permissionChangeReason} onChange={(event) => setPermissionChangeReason(event.target.value)} placeholder={t('roles.permissionPublication.reasonPlaceholder')} rows={3} />
          </Field>
          <DialogFooter>
            <Button variant='outline' onClick={() => setPermissionPublishOpen(false)}>{t('common.cancel')}</Button>
            <Button disabled={rolePublicationBusy || !permissionChangeReason.trim()} onClick={() => savePermissions.mutate()}>{t('roles.permissionPublication.publish')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <AlertDialog open={discardOpen} onOpenChange={setDiscardOpen}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{t('forms.discard.title')}</AlertDialogTitle><AlertDialogDescription>{t('forms.discard.desc')}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{t('forms.discard.keepEditing')}</AlertDialogCancel><AlertDialogAction onClick={() => { setDiscardOpen(false); setCreateOpen(false); reset({ name: '', code: '', description: '', businessReason: '' }) }}>{t('forms.discard.action')}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
      <AlertDialog open={policyDiscardOpen} onOpenChange={setPolicyDiscardOpen}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{t('roles.policyDiscard.title')}</AlertDialogTitle><AlertDialogDescription>{t('roles.policyDiscard.desc')}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel onClick={() => setPendingSelectedId(null)}>{t('forms.discard.keepEditing')}</AlertDialogCancel><AlertDialogAction onClick={() => { if (pendingSelectedId) setSelectedId(pendingSelectedId); setPendingSelectedId(null); setPolicyDiscardOpen(false) }}>{t('roles.policyDiscard.action')}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    </PageShell>
  )
}
