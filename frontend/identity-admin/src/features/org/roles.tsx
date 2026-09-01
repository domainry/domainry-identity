import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { zodResolver } from '@hookform/resolvers/zod'
import { useForm } from 'react-hook-form'
import type { ColumnDef } from '@tanstack/react-table'
import { FileText, Folder, Plus, Search, ShieldCheck } from 'lucide-react'
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
import { identityPoliciesApi, menusApi, objectsApi, permissionsApi, type RoleCreateInput } from '@/data/api'
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
import { DataScopesPage } from './data-scopes'
import { FieldPermissionsPage } from './field-permissions'
import { EffectiveAccessWorkspace } from './effective-access-workspace'
import { RoleGovernanceDetail } from './role-governance-detail'
import { buildPermissionCapabilityView } from './permission-capability-view'

interface RoleMenuRowProps {
  node: RoleMenuTreeNode
  selectedIDs: Set<string>
  disabled: boolean
  depth?: number
  onToggle: (menuID: string, checked: boolean) => void
  t: ReturnType<typeof useI18n>['t']
}

function RoleMenuRow({ node, selectedIDs, disabled, depth = 0, onToggle, t }: RoleMenuRowProps) {
  const state = roleMenuCheckState(node, selectedIDs)
  return (
    <>
      <div className='flex min-h-11 items-center gap-3 border-b px-3 py-2 last:border-b-0 hover:bg-muted/40' style={{ paddingInlineStart: `${12 + depth * 20}px` }}>
        <Checkbox
          aria-label={t('roles.menus.toggle', { name: displayText(t, node.name) })}
          checked={state}
          disabled={disabled}
          onCheckedChange={(checked) => onToggle(node.id, checked === true)}
        />
        {node.type === 'group' ? <Folder className='size-4 shrink-0 text-muted-foreground' /> : <FileText className='size-4 shrink-0 text-muted-foreground' />}
        <div className='min-w-0 flex-1'>
          <div className='flex flex-wrap items-center gap-2'>
            <span className='truncate text-sm font-medium'>{displayText(t, node.name)}</span>
            <Badge variant='outline' className='h-5 px-1.5 text-[10px]'>{node.type === 'group' ? t('menus.type.group') : t('menus.type.page')}</Badge>
            {!node.visible ? <Badge variant='secondary' className='h-5 px-1.5 text-[10px]'>{t('common.disabled')}</Badge> : null}
          </div>
          <div className='mt-0.5 flex min-w-0 flex-wrap gap-x-3 text-xs text-muted-foreground'>
            <code>{node.code}</code>
            {node.path ? <span className='truncate'>{node.path}</span> : null}
          </div>
        </div>
      </div>
      {node.children.map((child) => <RoleMenuRow key={child.id} node={child} selectedIDs={selectedIDs} disabled={disabled} depth={depth + 1} onToggle={onToggle} t={t} />)}
    </>
  )
}

export function RolesPage() {
  const { t } = useI18n()
  return (
    <Tabs defaultValue='role-policy' aria-label={t('roles.governanceTabs.label')}>
      <TabsList>
        <TabsTrigger value='role-policy'>{t('roles.governanceTabs.rolePolicy')}</TabsTrigger>
        <TabsTrigger value='data-scopes'>{t('roles.governanceTabs.dataScopes')}</TabsTrigger>
        <TabsTrigger value='field-permissions'>{t('roles.governanceTabs.fieldPermissions')}</TabsTrigger>
        <TabsTrigger value='effective-access'>{t('roles.governanceTabs.effectiveAccess')}</TabsTrigger>
      </TabsList>
      <TabsContent value='role-policy'>
        <RolePolicyWorkspace />
      </TabsContent>
      <TabsContent value='data-scopes'>
        <DataScopesPage />
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

function RolePolicyWorkspace() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [listQuery, setListQuery] = useState({ page: 1, pageSize: 10, search: '' })
  const rolesQuery = useRolePage({ ...listQuery, searchFields: ['label', 'key'] })
  const roles = rolesQuery.data?.items ?? []
  const roleTotal = rolesQuery.data?.total ?? 0
  const createRoleMut = useCreateRole()
  const [selectedId, setSelectedId] = useState('r1')
  const [draftPermissionKeys, setDraftPermissionKeys] = useState<string[]>([])
  const [permsDirty, setPermsDirty] = useState(false)
  const [permissionChangeReason, setPermissionChangeReason] = useState('')
  const [activePolicyTab, setActivePolicyTab] = useState<'overview' | 'permissions' | 'menus'>('overview')
  const [draftMenuIDs, setDraftMenuIDs] = useState<string[]>([])
  const [menusDirty, setMenusDirty] = useState(false)
  const [menuSearch, setMenuSearch] = useState('')
  const [pendingSelectedId, setPendingSelectedId] = useState<string | null>(null)
  const [policyDiscardOpen, setPolicyDiscardOpen] = useState(false)
  const [createOpen, setCreateOpen] = useState(false)
  const [discardOpen, setDiscardOpen] = useState(false)
  const [createPermissionKeys, setCreatePermissionKeys] = useState<string[]>([])
  const [createPermissionSearch, setCreatePermissionSearch] = useState('')
  const [createDataObject, setCreateDataObject] = useState('')
  const [createDataScope, setCreateDataScope] = useState('all_records')
  const [createDataWrite, setCreateDataWrite] = useState(false)
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
    businessReason: z.string().trim().min(1, t('roles.systemDraft.reasonRequired')),
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
      return identityPoliciesApi.saveRolePermissions(selected.id, draftPermissionKeys, permissionChangeReason.trim(), rolePermissionsQuery.data.schemaHash)
    },
    onSuccess: async (configuration) => {
      setDraftPermissionKeys(configuration.permissionKeys)
      setPermsDirty(false)
      setPermissionChangeReason('')
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
  const permissionCapabilities = useMemo(() => buildPermissionCapabilityView(permissionCatalogQuery.data ?? []), [permissionCatalogQuery.data])
  const permissionOperations = useMemo(() => permissionCapabilities.flatMap((capability) => capability.operations), [permissionCapabilities])
  const createPermissionOptions = useMemo(() => {
    const query = createPermissionSearch.trim().toLowerCase()
    return permissionOperations
      .filter((operation) => !query || `${operation.capabilityLabel} ${operation.operationLabel} ${operation.permissionKeys.join(' ')} ${operation.bindings.map((binding) => `${binding.method} ${binding.route}`).join(' ')}`.toLowerCase().includes(query))
      .slice(0, 100)
  }, [createPermissionSearch, permissionOperations])
  const createDataObjects = useMemo(() => schemaQuery.data?.objects ?? [], [schemaQuery.data?.objects])
  const menuTree = useMemo(() => buildRoleMenuTree(menusQuery.data ?? []), [menusQuery.data])
  const filteredMenuTree = useMemo(
    () => filterRoleMenuTree(menuTree, menuSearch, (node) => displayText(t, node.name)),
    [menuSearch, menuTree, t],
  )
  const selectedMenuIDs = useMemo(() => new Set(draftMenuIDs), [draftMenuIDs])
  useEffect(() => {
    setPermsDirty(false)
    setPermissionChangeReason('')
    setMenusDirty(false)
    setMenuSearch('')
  }, [selected?.id])
  useEffect(() => {
    if (permsDirty || !rolePermissionsQuery.data) return
    setDraftPermissionKeys(rolePermissionsQuery.data.permissionKeys)
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
        return <button className={cn('flex w-full items-center gap-2 rounded-md p-1 text-left', role.id === selected?.id && 'bg-accent')} onClick={() => requestRoleSelection(role.id)}><ShieldCheck className='size-4 shrink-0 text-muted-foreground' /><span className='min-w-0'><span className='flex items-center gap-1.5'><span className='truncate font-medium'>{displayText(t, role.name)}</span>{role.builtIn ? <Badge variant='secondary' className='px-1.5 text-[10px]'>{t('roles.builtIn')}</Badge> : null}</span><span className='block truncate text-xs text-muted-foreground'>{displayText(t, role.description) || t('roles.noDescription')}</span></span></button>
      },
    },
    { accessorKey: 'code', header: ({ column }) => <TableColumnHeader column={column} title={t('roles.form.code')} />, cell: ({ row }) => <code className='text-xs'>{row.original.code}</code> },
    { accessorKey: 'members', header: ({ column }) => <TableColumnHeader column={column} title={t('roles.list.title')} />, cell: ({ row }) => t('roles.memberCount', { count: row.original.members }) },
    { accessorKey: 'status', header: ({ column }) => <TableColumnHeader column={column} title={t('common.status')} />, cell: ({ row }) => <StatusBadge value={row.original.status}>{row.original.status === 'active' ? t('common.enabled') : t('common.disabled')}</StatusBadge> },
  ], [menusDirty, permsDirty, selected?.id, t])

  function togglePermissionKeys(permissionKeys: string[]) {
    if (!selected) return
    if (selected.builtIn) {
      toast.info(t('roles.toast.builtInLocked'))
      return
    }
    const next = new Set(draftPermissionKeys)
    const checked = permissionKeys.length > 0 && permissionKeys.every((key) => next.has(key))
    for (const key of permissionKeys) checked ? next.delete(key) : next.add(key)
    setDraftPermissionKeys([...next].sort())
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
    if (selected.builtIn) {
      toast.info(t('roles.toast.builtInLocked'))
      return
    }
    setDraftMenuIDs(toggleRoleMenuSelection(menusQuery.data ?? [], draftMenuIDs, menuID, checked))
    setMenusDirty(true)
  }

  function openCreateRole() {
    reset({ name: '', code: '', description: '', businessReason: '' })
    setCreatePermissionKeys([])
    setCreatePermissionSearch('')
    setCreateDataObject('')
    setCreateDataScope('all_records')
    setCreateDataWrite(false)
    setCreateOpen(true)
  }

  function requestCreateOpen(open: boolean) {
    if (!open && isDirty) setDiscardOpen(true)
    else setCreateOpen(open)
  }

  async function createRole(values: RoleFormValues) {
    if (createPermissionKeys.length === 0) {
      setError('root', { message: t('roles.validation.permissionRequired') })
      return
    }
    if (!createDataObject) {
      setError('root', { message: t('roles.validation.dataObjectRequired') })
      return
    }
    const input: RoleCreateInput = {
      name: values.name.trim(),
      code: values.code.trim().toUpperCase(),
      description: values.description.trim(),
      members: 0,
      builtIn: false,
      status: 'active',
      perms: {},
      businessReason: values.businessReason.trim(),
      permissionKeys: createPermissionKeys,
      dataPermission: {
        object_key: createDataObject,
        scope: createDataScope,
        read: createDataScope !== 'none',
        write: createDataScope !== 'none' && createDataWrite,
      },
    }
    try {
      await createRoleMut.mutateAsync(input)
      toast.success(t('roles.systemDraft.toast.saved'))
      setCreateOpen(false)
      reset({ name: '', code: '', description: '', businessReason: '' })
      setCreatePermissionKeys([])
      setCreateDataObject('')
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
                <Button size='sm' disabled={selected.builtIn || !permsDirty || rolePublicationBusy || !permissionChangeReason.trim()} onClick={() => savePermissions.mutate()}>{t('roles.permissionPublication.publish')}</Button>
              </div> : activePolicyTab === 'menus' ? <Button size='sm' disabled={selected.builtIn || !menusDirty || saveMenus.isPending} onClick={() => saveMenus.mutate()}>{menusDirty ? t('roles.menus.saveDirty') : t('roles.menus.save')}</Button> : null}
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
                <div className='mb-4 space-y-2 rounded-md border bg-muted/20 p-3'>
                  <div className='flex flex-wrap items-center justify-between gap-2'>
                    <div>
                      <p className='text-sm font-medium'>{t('roles.permissionPublication.title')}</p>
                      <p className='text-xs text-muted-foreground'>{t('roles.permissionPublication.description')}</p>
                    </div>
                  </div>
                  <Textarea aria-label={t('roles.permissionPublication.reason')} value={permissionChangeReason} onChange={(event) => setPermissionChangeReason(event.target.value)} placeholder={t('roles.permissionPublication.reasonPlaceholder')} rows={2} />
                </div>
                <div className='mb-3'>
                  <p className='text-xs font-medium tracking-wide text-muted-foreground uppercase'>{t('roles.capabilities.title')}</p>
                  <p className='mt-1 text-xs text-muted-foreground'>{t('roles.capabilities.description')}</p>
                </div>
                <div className='space-y-4'>
                  {permissionCapabilities.map((capability) => (
                    <section key={capability.key} className='overflow-hidden rounded-md border'>
                      <div className='border-b bg-muted/30 px-4 py-3'>
                        <p className='font-medium'>{capability.label}</p>
                      </div>
                      <div className='divide-y'>
                        {capability.operations.map((operation) => {
                          const checked = operation.permissionKeys.every((key) => draftPermissionKeys.includes(key))
                          const selectable = operation.active && operation.enabled
                          return <div key={operation.key} className='grid gap-3 p-4 md:grid-cols-[minmax(120px,0.35fr)_minmax(0,1fr)_auto]'>
                            <div>
                              <p className='text-sm font-medium'>{operation.operationLabel}</p>
                              <div className='mt-1 flex flex-wrap gap-1'>
                                <Badge variant={operation.active ? 'secondary' : 'outline'}>{operation.active ? t('roles.capabilities.active') : t('roles.capabilities.retired')}</Badge>
                                {!operation.enabled ? <Badge variant='destructive'>{t('roles.capabilities.disabled')}</Badge> : null}
                              </div>
                            </div>
                            <div className='space-y-2'>
                              {operation.bindings.map((binding) => <div key={binding.actionKey} className='rounded border bg-background px-3 py-2'>
                                <div className='flex flex-wrap items-center gap-2 text-sm'><Badge variant='outline'>{binding.method}</Badge><code className='break-all'>{binding.route || t('roles.capabilities.nonHttp')}</code></div>
                                <div className='mt-1 text-xs text-muted-foreground'>{binding.actionLabel}{binding.pageRoute ? ` · ${binding.pageLabel || t('roles.capabilities.page')} ${binding.pageRoute}` : ''}</div>
                              </div>)}
                              <details className='text-xs text-muted-foreground'><summary className='cursor-pointer'>{t('roles.capabilities.technicalDetails')}</summary><div className='mt-1 flex flex-wrap gap-1'>{operation.permissionKeys.map((key) => <code key={key} className='rounded bg-muted px-1.5 py-0.5'>{key}</code>)}</div></details>
                            </div>
                            <Checkbox aria-label={`${capability.label} - ${operation.operationLabel}`} checked={checked} disabled={selected.builtIn || rolePermissionsQuery.isPending || !selectable} onCheckedChange={() => togglePermissionKeys(operation.permissionKeys)} />
                          </div>
                        })}
                      </div>
                    </section>
                  ))}
                  {!permissionCapabilities.length ? <p className='rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground'>{t('roles.capabilities.empty')}</p> : null}
                </div>
                {selected.builtIn ? (
                  <p className='mt-3 text-xs text-muted-foreground'>{t('roles.builtInHint')}</p>
                ) : null}
              </TabsContent>
              <TabsContent value='menus' className='mt-3'>
                <div className='mb-3 flex flex-wrap items-center gap-2'>
                  <div className='relative min-w-[220px] flex-1'>
                    <Search className='pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted-foreground' />
                    <Input value={menuSearch} onChange={(event) => setMenuSearch(event.target.value)} placeholder={t('roles.menus.search')} className='pl-9' />
                  </div>
                  <Badge variant='secondary'>{t('roles.menus.selectedCount', { count: draftMenuIDs.length })}</Badge>
                  <Button variant='outline' size='sm' disabled={selected.builtIn || draftMenuIDs.length === 0} onClick={() => { setDraftMenuIDs([]); setMenusDirty(true) }}>
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
                    {filteredMenuTree.map((node) => <RoleMenuRow key={node.id} node={node} selectedIDs={selectedMenuIDs} disabled={selected.builtIn || saveMenus.isPending} onToggle={toggleMenu} t={t} />)}
                  </div>
                )}
                <p className='mt-3 text-xs text-muted-foreground'>{selected.builtIn ? t('roles.builtInHint') : t('roles.menus.hint')}</p>
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
              <FieldLabel htmlFor='role-business-reason'>{t('roles.systemDraft.reason')}</FieldLabel>
              <Textarea id='role-business-reason' placeholder={t('roles.create.reasonPlaceholder')} aria-invalid={Boolean(errors.businessReason)} {...register('businessReason')} />
              <FieldError errors={[errors.businessReason]} />
            </Field>
            <Field>
              <FieldLabel htmlFor='role-permission-search'>{t('roles.create.permissions')}</FieldLabel>
              <Input id='role-permission-search' value={createPermissionSearch} placeholder={t('roles.create.permissionsSearch')} onChange={(event) => setCreatePermissionSearch(event.target.value)} />
              <div className='max-h-48 space-y-1 overflow-y-auto rounded-md border p-2'>
                {createPermissionOptions.map((operation) => {
                  const checked = operation.permissionKeys.every((key) => createPermissionKeys.includes(key))
                  return <label key={operation.key} className='flex min-h-12 cursor-pointer items-start gap-2 rounded px-2 py-2 text-sm hover:bg-muted'>
                    <Checkbox className='mt-0.5' checked={checked} disabled={!operation.active || !operation.enabled} onCheckedChange={(next) => setCreatePermissionKeys((current) => { const values = new Set(current); for (const key of operation.permissionKeys) next === true ? values.add(key) : values.delete(key); return [...values].sort() })} />
                    <span className='min-w-0'><span className='block font-medium'>{operation.capabilityLabel} · {operation.operationLabel}</span><span className='block truncate text-xs text-muted-foreground'>{operation.bindings.map((binding) => `${binding.method} ${binding.route}`).join(' · ')}</span></span>
                  </label>
                })}
              </div>
              <p className='text-xs text-muted-foreground'>{t('roles.create.permissionsSelected', { count: createPermissionKeys.length })}</p>
            </Field>
            <div className='grid gap-4 sm:grid-cols-2'>
              <Field>
                <FieldLabel>{t('roles.create.dataObject')}</FieldLabel>
                <Select value={createDataObject} onValueChange={setCreateDataObject}>
                  <SelectTrigger><SelectValue placeholder={t('roles.create.dataObjectPlaceholder')} /></SelectTrigger>
                  <SelectContent>{createDataObjects.map((object) => <SelectItem key={object.key} value={object.key}>{object.name || object.label || object.key}</SelectItem>)}</SelectContent>
                </Select>
              </Field>
              <Field>
                <FieldLabel>{t('roles.create.dataScope')}</FieldLabel>
                <Select value={createDataScope} onValueChange={setCreateDataScope}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent><SelectItem value='all_records'>{t('roles.create.scopeAll')}</SelectItem><SelectItem value='owned_records'>{t('roles.create.scopeOwned')}</SelectItem><SelectItem value='none'>{t('common.none')}</SelectItem></SelectContent>
                </Select>
              </Field>
            </div>
            <label className='flex items-center gap-2 text-sm'><Checkbox checked={createDataWrite} onCheckedChange={(checked) => setCreateDataWrite(checked === true)} />{t('roles.create.dataWrite')}</label>
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
      <AlertDialog open={discardOpen} onOpenChange={setDiscardOpen}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{t('forms.discard.title')}</AlertDialogTitle><AlertDialogDescription>{t('forms.discard.desc')}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>{t('forms.discard.keepEditing')}</AlertDialogCancel><AlertDialogAction onClick={() => { setDiscardOpen(false); setCreateOpen(false); reset({ name: '', code: '', description: '', businessReason: '' }) }}>{t('forms.discard.action')}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
      <AlertDialog open={policyDiscardOpen} onOpenChange={setPolicyDiscardOpen}><AlertDialogContent><AlertDialogHeader><AlertDialogTitle>{t('roles.policyDiscard.title')}</AlertDialogTitle><AlertDialogDescription>{t('roles.policyDiscard.desc')}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><AlertDialogCancel onClick={() => setPendingSelectedId(null)}>{t('forms.discard.keepEditing')}</AlertDialogCancel><AlertDialogAction onClick={() => { if (pendingSelectedId) setSelectedId(pendingSelectedId); setPendingSelectedId(null); setPolicyDiscardOpen(false) }}>{t('roles.policyDiscard.action')}</AlertDialogAction></AlertDialogFooter></AlertDialogContent></AlertDialog>
    </PageShell>
  )
}
