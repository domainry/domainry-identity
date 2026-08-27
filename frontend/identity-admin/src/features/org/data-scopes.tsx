import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Send, ShieldCheck, Upload } from 'lucide-react'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Textarea,
} from '@domainry/ui'
import { PageShell } from '@/components/page-shell'
import { PageQueryState } from '@/components/page-query-state'
import { DataTableToolbar, DATA_TABLE_TOOLBAR_CONTROL_CLASS } from '@/components/data-table'
import {
  authoringParameter,
  identityPoliciesApi,
  objectsApi,
  permissionsApi,
  platformCapabilitiesApi,
  rolesApi,
  type RuntimeDataScopePolicy,
} from '@/data/api'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { runtimeApiError } from '@/lib/runtime-api'
import {
  buildRoleAuthorizationBatchChangePlan,
  roleAuthorizationPlanID,
  systemChangePlansApi,
  type RuntimeChangePlanDraft,
  type RuntimeManifestRole,
} from '@/data/action-definition-api'
import {
  dataScopeValues,
  effectiveObjectPermission,
  effectiveObjectScope,
  isDataScopeOptionDisabled,
  objectCrudActions,
  roleHasImplicitObjectAccess,
  shouldHydrateRoleAuthorizationDraft,
} from './data-scopes-view-model'

type ScopeType = string

const SCOPE_LABEL_KEYS: Record<string, MessageKey> = {
  all_records: 'scopes.type.all',
  department_and_children: 'scopes.type.deptTree',
  department: 'scopes.type.dept',
  owned_records: 'scopes.type.self',
  subordinates: 'scopes.type.subordinates',
  team: 'scopes.type.team',
  custom: 'scopes.type.custom',
  none: 'scopes.type.none',
}
type RoleDraft = { permissionKeys: string[]; items: RuntimeDataScopePolicy[] }

export function DataScopesPage() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [roleFilter, setRoleFilter] = useState('__all__')
  const [drafts, setDrafts] = useState<Record<string, RoleDraft>>({})
  const [dirtyRoles, setDirtyRoles] = useState<Set<string>>(new Set())
  const [changeReason, setChangeReason] = useState('')
  const query = useQuery({
    queryKey: ['runtime', 'identity', 'data-scopes'],
    queryFn: async () => {
      const [roles, schema, permissionCatalog, capabilities] = await Promise.all([rolesApi.list(), objectsApi.schemaSnapshot(), permissionsApi.catalog(), platformCapabilitiesApi.get()])
      const policies = await Promise.all(
        roles.map(async (role) => {
          const [items, permissionKeys] = await Promise.all([
            identityPoliciesApi.dataScopes(role.id),
            identityPoliciesApi.rolePermissions(role.id),
          ])
          return { role, items, permissionKeys }
        })
      )
      const objects = (schema.objects ?? []).filter((object) => object.config?.system_object !== true)
      return {
        roles,
        objects,
        permissionCatalog,
        actions: objectCrudActions(objects.map((object) => object.key), permissionCatalog),
        scopeValues: authoringParameter(capabilities, 'identity.role_data_scope', 'data_scope')?.enum ?? [],
        policies,
      }
    },
  })
  const snapshotQuery = useQuery({ queryKey: ['runtime', 'system-snapshot'], queryFn: systemChangePlansApi.snapshot })
  const graphQuery = useQuery({ queryKey: ['runtime', 'reference-graph'], queryFn: systemChangePlansApi.graph })
  const planID = useMemo(() => roleAuthorizationPlanID(snapshotQuery.data?.snapshot_hash ?? ''), [snapshotQuery.data?.snapshot_hash])
  const draftQuery = useQuery({
    queryKey: ['runtime', 'change-plan', planID],
    queryFn: async (): Promise<RuntimeChangePlanDraft | null> => {
      try { return await systemChangePlansApi.get(planID) } catch (error) {
        if (runtimeApiError(error)?.status === 404) return null
        throw error
      }
    },
    enabled: Boolean(planID), retry: false,
  })
  const systemDraft = draftQuery.data
  useEffect(() => {
    if (!query.data || shouldHydrateRoleAuthorizationDraft(systemDraft?.status) || dirtyRoles.size) return
    setDrafts(Object.fromEntries(query.data.policies.map(({ role, items, permissionKeys }) => [role.id, { items, permissionKeys }])))
  }, [dirtyRoles.size, query.data, systemDraft])
  useEffect(() => {
    if (!query.data || !systemDraft || !shouldHydrateRoleAuthorizationDraft(systemDraft.status)) return
    const next = Object.fromEntries(query.data.policies.map(({ role, items, permissionKeys }) => [role.id, { items, permissionKeys }]))
    const dirty = new Set<string>()
    for (const item of systemDraft.payload.items) {
      if (item.resource_type !== 'role') continue
      const role = query.data.roles.find((candidate) => candidate.code === item.resource_key)
      const after = item.after as RuntimeManifestRole | undefined
      if (!role || !after) continue
      next[role.id] = {
        permissionKeys: [...(after.permissions ?? [])],
        items: (after.data_permissions ?? []).map((scope) => ({ resource: scope.object_key, scope: scope.scope, audit_denial: scope.audit_denial, predicate: scope.predicate as RuntimeDataScopePolicy['predicate'] })),
      }
      dirty.add(role.id)
    }
    setDrafts(next)
    setDirtyRoles(dirty)
    setChangeReason(systemDraft.payload.business_reason)
  }, [query.data, systemDraft])

  const save = useMutation({
    mutationFn: async () => {
      if (!query.data || !snapshotQuery.data || !graphQuery.data || !planID || !changeReason.trim()) throw new Error('system-draft-not-ready')
      const changes = [...dirtyRoles].map((roleID) => {
        const role = query.data!.roles.find((candidate) => candidate.id === roleID)!
        const draft = drafts[roleID]
        return { roleKey: role.code, roleName: String(role.name), permissionKeys: draft.permissionKeys, dataScopes: draft.items }
      })
      const plan = buildRoleAuthorizationBatchChangePlan({ snapshot: snapshotQuery.data, graph: graphQuery.data, changes, reason: changeReason.trim(), planID, existingDraft: systemDraft })
      const validation = await systemChangePlansApi.validate(plan)
      const blockingIssues = validation.issues.filter((issue) => issue.code !== 'backend.change_plan.review_required')
      if (blockingIssues.length || (validation.valid && !validation.apply_allowed)) throw new Error('plan-invalid')
      return systemChangePlansApi.save(plan, systemDraft?.revision ?? 0)
    },
    onSuccess: (saved) => { queryClient.setQueryData(['runtime', 'change-plan', planID], saved); toast.success(t('roles.systemDraft.toast.saved')) },
    onError: () => toast.error(t('roles.systemDraft.toast.failed')),
  })
  const review = useMutation({ mutationFn: () => systemChangePlansApi.review(systemDraft!), onSuccess: ({ draft }) => { queryClient.setQueryData(['runtime', 'change-plan', planID], draft); toast.success(t('roles.systemDraft.toast.reviewed')) }, onError: () => toast.error(t('roles.systemDraft.toast.failed')) })
  const approve = useMutation({ mutationFn: () => systemChangePlansApi.approve(systemDraft!), onSuccess: ({ draft }) => { queryClient.setQueryData(['runtime', 'change-plan', planID], draft); toast.success(t('roles.systemDraft.toast.approved')) }, onError: () => toast.error(t('roles.systemDraft.toast.failed')) })
  const publish = useMutation({
    mutationFn: () => systemChangePlansApi.publish(systemDraft!),
    onSuccess: async () => {
      setDirtyRoles(new Set()); setChangeReason('')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['runtime', 'identity', 'data-scopes'] }),
        queryClient.invalidateQueries({ queryKey: ['runtime', 'permissions', 'effective'] }),
        queryClient.invalidateQueries({ queryKey: ['runtime', 'system-snapshot'] }),
        queryClient.invalidateQueries({ queryKey: ['runtime', 'reference-graph'] }),
      ])
      toast.success(t('roles.systemDraft.toast.published'))
    },
    onError: () => toast.error(t('roles.systemDraft.toast.failed')),
  })

  const rows = useMemo(() => {
    if (!query.data) return []
    return query.data.policies.flatMap(({ role, items, permissionKeys }) => {
      const draft = drafts[role.id] ?? { items, permissionKeys }
      return query.data.objects.map((object) => ({
        role,
        object,
        scope: effectiveObjectScope(role, draft.permissionKeys, draft.items.find((item) => item.resource === object.key)?.scope ?? ('none' as const)),
        policies: draft.items,
        permissionKeys: draft.permissionKeys,
      }))
    })
  }, [drafts, query.data])
  const visible = rows.filter((row) => roleFilter === '__all__' || row.role.id === roleFilter)

  function updateRole(roleID: string, update: (draft: RoleDraft) => RoleDraft) {
    const source = drafts[roleID]
    if (!source) return
    setDrafts((current) => ({ ...current, [roleID]: update(current[roleID] ?? source) }))
    setDirtyRoles((current) => new Set(current).add(roleID))
  }

  function permissionPoint(objectKey: string, action: string) {
    return query.data?.permissionCatalog.find((permission) => permission.resource === objectKey && permission.action === action)
  }

  function setPermission(roleID: string, objectKey: string, action: string, checked: boolean) {
    const point = permissionPoint(objectKey, action)
    if (!point) return
    updateRole(roleID, (draft) => {
      const next = new Set(draft.permissionKeys)
      if (checked) next.add(point.key)
      else next.delete(point.key)
      return { ...draft, permissionKeys: [...next].sort() }
    })
  }

  function setScope(roleID: string, objectKey: string, scope: ScopeType) {
    updateRole(roleID, (draft) => ({
      ...draft,
      items: scope === 'none'
        ? draft.items.filter((item) => item.resource !== objectKey)
        : [...draft.items.filter((item) => item.resource !== objectKey), { resource: objectKey, scope }],
    }))
  }

  function setRow(roleID: string, objectKey: string, checked: boolean) {
    for (const action of query.data?.actions ?? []) setPermission(roleID, objectKey, action, checked)
  }

  function setColumn(action: string, checked: boolean) {
    for (const row of visible) {
      if (roleHasImplicitObjectAccess(row.role, row.permissionKeys)) continue
      setPermission(row.role.id, row.object.key, action, checked)
    }
  }

  function columnIsChecked(action: string) {
    const editablePoints = visible.flatMap((row) => {
      if (roleHasImplicitObjectAccess(row.role, row.permissionKeys)) return []
      const point = permissionPoint(row.object.key, action)
      return point ? [{ point, permissionKeys: row.permissionKeys }] : []
    })
    return editablePoints.length > 0 && editablePoints.every(({ point, permissionKeys }) => permissionKeys.includes(point.key))
  }

  function rowIsChecked(row: (typeof visible)[number]) {
    const points = (query.data?.actions ?? []).map((action) => permissionPoint(row.object.key, action)).filter((point) => point !== undefined)
    return points.length > 0 && points.every((point) => row.permissionKeys.includes(point.key))
  }

  if (!query.data) return <PageQueryState title={t('scopes.title')} description={t('scopes.desc')} error={query.error} onRetry={() => void query.refetch()} />
  const data = query.data
  const scopeValues = dataScopeValues(
    data.scopeValues,
    data.policies.flatMap(({ items }) => items.map((item) => item.scope)),
  )
  const actionLabel = (action: string) => t(`scopes.action.${action}` as MessageKey)
  const policyLocked = Boolean(systemDraft && systemDraft.status !== 'draft')
  const busy = save.isPending || review.isPending || approve.isPending || publish.isPending

  return (
    <PageShell title={t('scopes.title')} description={t('scopes.desc')}>
      <Card>
        <CardHeader className='gap-3 pb-3'>
          <div>
            <CardTitle className='text-base'>{t('scopes.matrixTitle')}</CardTitle>
            <CardDescription>{t('scopes.matrixDescription')}</CardDescription>
          </div>
          <Textarea aria-label={t('roles.systemDraft.reason')} value={changeReason} onChange={(event) => setChangeReason(event.target.value)} placeholder={t('roles.systemDraft.reasonPlaceholder')} disabled={policyLocked} rows={2} />
          {systemDraft ? <Badge variant='outline'>{t('roles.systemDraft.status', { status: systemDraft.status, revision: systemDraft.revision })}</Badge> : null}
          <DataTableToolbar
            filters={<Select value={roleFilter} onValueChange={setRoleFilter}>
              <SelectTrigger className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-52`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value='__all__'>{t('scopes.filter.allRoles')}</SelectItem>
                  {data.roles.map((role) => (
                    <SelectItem key={role.id} value={role.id}>{role.name}</SelectItem>
                  ))}
                </SelectGroup>
              </SelectContent>
            </Select>}
            actions={<>
            <span className='text-xs text-muted-foreground'>
              {t('common.count', { count: visible.length })}
            </span>
            {(!systemDraft || systemDraft.status === 'draft') ? <Button variant='outline' disabled={!dirtyRoles.size || busy || policyLocked} onClick={() => { setDirtyRoles(new Set()); if (query.data) setDrafts(Object.fromEntries(query.data.policies.map(({ role, items, permissionKeys }) => [role.id, { items, permissionKeys }]))) }}>{t('scopes.discard')}</Button> : null}
            {(!systemDraft || systemDraft.status === 'draft') ? <Button disabled={!dirtyRoles.size || busy || !changeReason.trim()} onClick={() => save.mutate()}>{t('roles.systemDraft.save')}</Button> : null}
            {systemDraft?.status === 'draft' ? <Button disabled={busy} onClick={() => review.mutate()}><Send data-icon='inline-start' />{t('roles.systemDraft.review')}</Button> : null}
            {systemDraft?.status === 'in_review' ? <Button disabled={busy} onClick={() => approve.mutate()}><ShieldCheck data-icon='inline-start' />{t('roles.systemDraft.approve')}</Button> : null}
            {systemDraft?.status === 'approved' ? <Button disabled={busy} onClick={() => publish.mutate()}><Upload data-icon='inline-start' />{t('roles.systemDraft.publish')}</Button> : null}
            </>}
          />
        </CardHeader>
        <CardContent className='flex flex-col gap-3'>
          <div className='max-w-full overflow-x-auto rounded-md border overscroll-x-contain [&>[data-slot=table-container]]:overflow-visible'>
            <Table className='min-w-[1136px] table-fixed'>
              <TableHeader>
                <TableRow>
                  <TableHead className='sticky left-0 z-20 w-48 bg-background'>{t('scopes.table.role')}</TableHead>
                  <TableHead className='w-52'>{t('scopes.table.module')}</TableHead>
                  <TableHead className='w-56'>{t('scopes.table.scope')}</TableHead>
                  {data.actions.map((action) => (
                    <TableHead key={action} className='w-24 whitespace-nowrap text-center'>
                      <Button size='sm' variant='ghost' className='h-7 whitespace-nowrap px-2 text-xs' disabled={policyLocked} onClick={() => setColumn(action, !columnIsChecked(action))}>
                        {actionLabel(action)}
                      </Button>
                    </TableHead>
                  ))}
                  <TableHead className='w-32 whitespace-nowrap text-center'>{t('scopes.selectPermissions')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((row) => (
                  <TableRow key={`${row.role.id}:${row.object.key}`} className='group hover:bg-muted/50'>
                    <TableCell className='sticky left-0 z-10 bg-background group-hover:bg-muted'>
                      <div className='flex flex-wrap items-center gap-1.5'>
                        <Badge variant={dirtyRoles.has(row.role.id) ? 'default' : 'secondary'}>{row.role.name}</Badge>
                        {roleHasImplicitObjectAccess(row.role, row.permissionKeys) ? <Badge variant='outline'>{t('scopes.inheritedAdmin')}</Badge> : null}
                      </div>
                    </TableCell>
                    <TableCell className='font-medium'>{row.object.label || row.object.name || row.object.key}</TableCell>
                    <TableCell>
                      <Select value={row.scope} disabled={busy || policyLocked || roleHasImplicitObjectAccess(row.role, row.permissionKeys)} onValueChange={(scope) => setScope(row.role.id, row.object.key, scope as ScopeType)}>
                        <SelectTrigger data-policy-control={`${row.role.id}:${row.object.key}:scope`} size='sm' className='w-48'><SelectValue /></SelectTrigger>
                        <SelectContent><SelectGroup>{scopeValues.map((scope) => {
                          return <SelectItem key={scope} value={scope} disabled={isDataScopeOptionDisabled(scope, row.scope, row.policies, row.object.key)}>
                            {SCOPE_LABEL_KEYS[scope] ? t(SCOPE_LABEL_KEYS[scope]) : scope}
                          </SelectItem>
                        })}</SelectGroup></SelectContent>
                      </Select>
                    </TableCell>
                    {data.actions.map((action) => {
                      const point = data.permissionCatalog.find((permission) => permission.resource === row.object.key && permission.action === action)
                      const inherited = roleHasImplicitObjectAccess(row.role, row.permissionKeys)
                      return (
                        <TableCell key={action} className='text-center'>
                          <Switch data-policy-control={`${row.role.id}:${row.object.key}:${action}`} aria-label={`${row.role.name} ${row.object.key} ${actionLabel(action)}`} checked={effectiveObjectPermission(row.role, row.permissionKeys, point)} disabled={!point || inherited || busy || policyLocked} onCheckedChange={(checked) => setPermission(row.role.id, row.object.key, action, checked)} />
                        </TableCell>
                      )
                    })}
                    <TableCell className='text-center'>
                      <Button size='sm' variant='outline' className='h-7 whitespace-nowrap px-2 text-xs' disabled={busy || policyLocked || roleHasImplicitObjectAccess(row.role, row.permissionKeys)} onClick={() => setRow(row.role.id, row.object.key, !rowIsChecked(row))}>{t('scopes.selectPermissions')}</Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          <div className='space-y-1 text-xs text-muted-foreground'>
            <p>{t('scopes.hint')}</p>
            <p>{t('scopes.editorLimits')}</p>
          </div>
        </CardContent>
      </Card>
    </PageShell>
  )
}
