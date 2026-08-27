import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { Send, ShieldCheck, Upload } from 'lucide-react'
import {
  Badge,
  Button,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Skeleton,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
  Textarea,
} from '@domainry/ui'
import { PageShell } from '@/components/page-shell'
import { PageQueryState } from '@/components/page-query-state'
import { EmptyState } from '@/components/empty-state'
import {
  identityPoliciesApi,
  objectsApi,
  rolesApi,
  type RuntimeFieldPermission,
} from '@/data/api'
import { useI18n } from '@/lib/i18n'
import { runtimeApiError } from '@/lib/runtime-api'
import {
  buildRoleAuthorizationChangePlan,
  roleAuthorizationPlanID,
  systemChangePlansApi,
  type RuntimeChangePlanDraft,
  type RuntimeManifestRole,
} from '@/data/action-definition-api'
import { shouldHydrateRoleAuthorizationDraft } from './data-scopes-view-model'

export function FieldPermissionsPage() {
  const { t } = useI18n()
  const client = useQueryClient()
  const [roleID, setRoleID] = useState('')
  const [objectKey, setObjectKey] = useState('')
  const [draftPermissions, setDraftPermissions] = useState<RuntimeFieldPermission[]>([])
  const [dirty, setDirty] = useState(false)
  const [changeReason, setChangeReason] = useState('')
  const setup = useQuery({
    queryKey: ['runtime', 'identity', 'field-permissions', 'setup'],
    queryFn: async () => {
      const [roles, schema] = await Promise.all([rolesApi.list(), objectsApi.schemaSnapshot()])
      return { roles, objects: schema.objects ?? [] }
    },
  })
  useEffect(() => {
    if (!roleID && setup.data?.roles[0]) setRoleID(setup.data.roles[0].id)
    if (!objectKey && setup.data?.objects[0]) setObjectKey(setup.data.objects[0].key)
  }, [objectKey, roleID, setup.data])
  useEffect(() => {
    setDirty(false)
    setChangeReason('')
  }, [roleID])
  const permissions = useQuery({
    queryKey: ['runtime', 'identity', 'field-permissions', roleID],
    queryFn: () => identityPoliciesApi.fieldPermissions(roleID),
    enabled: Boolean(roleID),
  })
  const selectedRole = setup.data?.roles.find((role) => role.id === roleID)
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
  const activeSystemDraft = shouldHydrateRoleAuthorizationDraft(systemDraft?.status) ? systemDraft : null
  useEffect(() => {
    const selectedInDraft = activeSystemDraft?.payload.items.some((item) => item.resource_type === 'role' && item.resource_key === selectedRole?.code)
    if (selectedInDraft || dirty || !permissions.data) return
    setDraftPermissions(permissions.data)
  }, [activeSystemDraft, dirty, permissions.data, selectedRole?.code])
  useEffect(() => {
    if (!activeSystemDraft || !selectedRole) return
    const item = activeSystemDraft.payload.items.find((candidate) => candidate.resource_type === 'role' && candidate.resource_key === selectedRole.code)
    const after = item?.after as RuntimeManifestRole | undefined
    if (after) {
      setDraftPermissions((after.field_permissions ?? []).map((permission) => ({
        resource: permission.object_key, field: permission.field_key, visible: permission.read, editable: permission.write,
        masked: permission.masked, policies: permission.policies as RuntimeFieldPermission['policies'],
      })))
    } else if (permissions.data) {
      setDraftPermissions(permissions.data)
    }
    setChangeReason(activeSystemDraft.payload.business_reason)
    setDirty(Boolean(after))
  }, [activeSystemDraft, permissions.data, selectedRole])
  const save = useMutation({
    mutationFn: async () => {
      if (!selectedRole || !snapshotQuery.data || !graphQuery.data || !planID || !changeReason.trim()) throw new Error('system-draft-not-ready')
      const plan = buildRoleAuthorizationChangePlan({ snapshot: snapshotQuery.data, graph: graphQuery.data, roleKey: selectedRole.code, roleName: String(selectedRole.name), fieldPermissions: draftPermissions, reason: changeReason.trim(), planID, existingDraft: activeSystemDraft })
      const validation = await systemChangePlansApi.validate(plan)
      const blockingIssues = validation.issues.filter((issue) => issue.code !== 'backend.change_plan.review_required')
      if (blockingIssues.length || (validation.valid && !validation.apply_allowed)) throw new Error('plan-invalid')
      return systemChangePlansApi.save(plan, activeSystemDraft?.revision ?? 0)
    },
    onSuccess: (saved) => { client.setQueryData(['runtime', 'change-plan', planID], saved); toast.success(t('roles.systemDraft.toast.saved')) },
    onError: () => toast.error(t('roles.systemDraft.toast.failed')),
  })
  const review = useMutation({ mutationFn: () => systemChangePlansApi.review(activeSystemDraft!), onSuccess: ({ draft }) => { client.setQueryData(['runtime', 'change-plan', planID], draft); toast.success(t('roles.systemDraft.toast.reviewed')) }, onError: () => toast.error(t('roles.systemDraft.toast.failed')) })
  const approve = useMutation({ mutationFn: () => systemChangePlansApi.approve(activeSystemDraft!), onSuccess: ({ draft }) => { client.setQueryData(['runtime', 'change-plan', planID], draft); toast.success(t('roles.systemDraft.toast.approved')) }, onError: () => toast.error(t('roles.systemDraft.toast.failed')) })
  const publish = useMutation({
    mutationFn: () => systemChangePlansApi.publish(activeSystemDraft!),
    onSuccess: async () => {
      setDirty(false); setChangeReason('')
      await Promise.all([
        client.invalidateQueries({ queryKey: ['runtime', 'identity', 'field-permissions', roleID] }),
        client.invalidateQueries({ queryKey: ['runtime', 'permissions', 'effective'] }),
        client.invalidateQueries({ queryKey: ['runtime', 'system-snapshot'] }),
        client.invalidateQueries({ queryKey: ['runtime', 'reference-graph'] }),
      ])
      toast.success(t('roles.systemDraft.toast.published'))
    },
    onError: () => toast.error(t('roles.systemDraft.toast.failed')),
  })

  const current = useMemo(
    () => new Map(draftPermissions.map((item) => [`${item.resource}:${item.field}`, item])),
    [draftPermissions]
  )

  function updateField(resource: string, field: string, patch: Partial<RuntimeFieldPermission>) {
    const key = `${resource}:${field}`
    const previous = current.get(key) ?? { resource, field, visible: true, editable: true, masked: false }
    const next = { ...previous, ...patch }
    if (!next.visible) next.editable = false
    if (next.editable) next.visible = true
    setDraftPermissions((items) => [...items.filter((item) => `${item.resource}:${item.field}` !== key), next])
    setDirty(true)
  }

  if (!setup.data) return <PageQueryState title={t('fieldPerms.title')} description={t('fieldPerms.desc')} error={setup.error} onRetry={() => void setup.refetch()} />
  const data = setup.data
  const roleLocked = Boolean(selectedRole?.builtIn)
  const policyLocked = roleLocked || Boolean(activeSystemDraft && activeSystemDraft.status !== 'draft')
  const busy = save.isPending || review.isPending || approve.isPending || publish.isPending

  return (
    <PageShell
      title={t('fieldPerms.title')}
      description={t('fieldPerms.desc')}
      actions={
        <Select value={roleID} onValueChange={setRoleID}>
          <SelectTrigger className='w-52'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {data.roles.map((role) => (
                <SelectItem key={role.id} value={role.id}>{role.name}</SelectItem>
              ))}
            </SelectGroup>
          </SelectContent>
        </Select>
      }
    >
      <div className='mb-4 space-y-3 rounded-md border bg-muted/20 p-3'>
        <div className='flex flex-wrap items-center justify-between gap-2'>
          <div><p className='text-sm font-medium'>{t('roles.systemDraft.title')}</p><p className='text-xs text-muted-foreground'>{t('roles.systemDraft.description')}</p></div>
          <div className='flex flex-wrap items-center gap-2'>
            {roleLocked ? <Badge variant='outline'>{t('scopes.inheritedAdmin')}</Badge> : null}
            {activeSystemDraft ? <Badge variant='outline'>{t('roles.systemDraft.status', { status: activeSystemDraft.status, revision: activeSystemDraft.revision })}</Badge> : null}
          </div>
        </div>
        <Textarea aria-label={t('roles.systemDraft.reason')} value={changeReason} onChange={(event) => setChangeReason(event.target.value)} placeholder={t('roles.systemDraft.reasonPlaceholder')} disabled={policyLocked} rows={2} />
        <div className='flex flex-wrap justify-end gap-2'>
          {(!activeSystemDraft || activeSystemDraft.status === 'draft') ? <Button variant='outline' disabled={!dirty || busy || policyLocked} onClick={() => { setDraftPermissions(permissions.data ?? []); setDirty(false) }}>{t('scopes.discard')}</Button> : null}
          {(!activeSystemDraft || activeSystemDraft.status === 'draft') ? <Button disabled={!dirty || busy || policyLocked || !changeReason.trim()} onClick={() => save.mutate()}>{t('roles.systemDraft.save')}</Button> : null}
          {activeSystemDraft?.status === 'draft' ? <Button disabled={busy} onClick={() => review.mutate()}><Send data-icon='inline-start' />{t('roles.systemDraft.review')}</Button> : null}
          {activeSystemDraft?.status === 'in_review' ? <Button disabled={busy} onClick={() => approve.mutate()}><ShieldCheck data-icon='inline-start' />{t('roles.systemDraft.approve')}</Button> : null}
          {activeSystemDraft?.status === 'approved' ? <Button disabled={busy} onClick={() => publish.mutate()}><Upload data-icon='inline-start' />{t('roles.systemDraft.publish')}</Button> : null}
        </div>
      </div>
      <Tabs value={objectKey} onValueChange={setObjectKey}>
        <div className='max-w-full overflow-x-auto overscroll-x-contain'>
          <TabsList>
            {data.objects.map((object) => (
              <TabsTrigger key={object.key} value={object.key}>
                {object.label || object.name || object.key}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
        {data.objects.map((object) => (
          <TabsContent key={object.key} value={object.key}>
            {permissions.isPending ? <Skeleton className='h-64 w-full rounded-lg' /> : object.fields.length === 0 ? (
              <EmptyState title={t('common.emptyTitle')} description={t('common.emptyDesc')} />
            ) : (
              <div className='max-h-[600px] overflow-auto'>
                <Table>
                  <TableHeader className='sticky top-0 z-10 bg-background'>
                    <TableRow>
                      <TableHead>{t('fieldPerms.table.field')}</TableHead>
                      <TableHead>{t('fieldPerms.table.code')}</TableHead>
                      <TableHead>{t('fieldPerms.table.visible')}</TableHead>
                      <TableHead>{t('fieldPerms.table.editable')}</TableHead>
                      <TableHead>{t('fieldPerms.table.masked')}</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {object.fields.map((field) => {
                      const policy = current.get(`${object.key}:${field.key}`)
                      const visible = policy?.visible ?? true
                      const editable = policy?.editable ?? true
                      const masked = policy?.masked ?? false
                      return (
                        <TableRow key={field.key}>
                          <TableCell className='font-medium'>
                            <span className='flex items-center gap-2'>
                              {field.label || field.name || field.key}
                              {masked ? <Badge variant='outline'>{t('fieldPerms.sensitive')}</Badge> : null}
                            </span>
                          </TableCell>
                          <TableCell><code className='rounded bg-muted px-1.5 py-0.5 text-xs'>{field.key}</code></TableCell>
                          <TableCell><Switch aria-label={`${field.label || field.name || field.key} ${t('fieldPerms.table.visible')}`} data-field-permission-control={`${object.key}:${field.key}:visible`} checked={visible} disabled={busy || policyLocked} onCheckedChange={(value) => updateField(object.key, field.key, { visible: value })} /></TableCell>
                          <TableCell><Switch aria-label={`${field.label || field.name || field.key} ${t('fieldPerms.table.editable')}`} data-field-permission-control={`${object.key}:${field.key}:editable`} checked={editable} disabled={busy || policyLocked} onCheckedChange={(value) => updateField(object.key, field.key, { editable: value })} /></TableCell>
                          <TableCell><Switch aria-label={`${field.label || field.name || field.key} ${t('fieldPerms.table.masked')}`} data-field-permission-control={`${object.key}:${field.key}:masked`} checked={masked} disabled={busy || policyLocked} onCheckedChange={(value) => updateField(object.key, field.key, { masked: value })} /></TableCell>
                        </TableRow>
                      )
                    })}
                  </TableBody>
                </Table>
              </div>
            )}
            <p className='mt-3 text-xs text-muted-foreground'>{t('fieldPerms.hint')}</p>
          </TabsContent>
        ))}
      </Tabs>
    </PageShell>
  )
}
