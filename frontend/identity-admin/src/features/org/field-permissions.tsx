import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
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

  const configuration = useQuery({
    queryKey: ['runtime', 'identity', 'field-permissions', roleID],
    queryFn: () => identityPoliciesApi.fieldPermissionConfiguration(roleID),
    enabled: Boolean(roleID),
  })
  useEffect(() => {
    if (dirty || !configuration.data) return
    setDraftPermissions(configuration.data.fieldPermissions)
  }, [configuration.data, dirty])

  const publish = useMutation({
    mutationFn: async () => {
      if (!configuration.data?.schemaHash || !changeReason.trim()) throw new Error('role-policy-publication-not-ready')
      return identityPoliciesApi.saveFieldPermissions(roleID, draftPermissions, changeReason.trim(), configuration.data.schemaHash)
    },
    onSuccess: async (published) => {
      setDraftPermissions(published.fieldPermissions)
      setDirty(false)
      setChangeReason('')
      client.setQueryData(['runtime', 'identity', 'field-permissions', roleID], published)
      await Promise.all([
        client.invalidateQueries({ queryKey: ['runtime', 'identity', 'field-permissions', roleID] }),
        client.invalidateQueries({ queryKey: ['runtime', 'permissions', 'effective'] }),
      ])
      toast.success(t('roles.policyPublication.toast.published'))
    },
    onError: () => toast.error(t('roles.policyPublication.toast.failed')),
  })

  const current = useMemo(
    () => new Map(draftPermissions.map((item) => [`${item.resource}:${item.field}`, item])),
    [draftPermissions],
  )

  function updateField(resource: string, field: string, patch: Partial<RuntimeFieldPermission>) {
    const key = `${resource}:${field}`
    const object = setup.data?.objects.find((candidate) => candidate.key === resource)
    const definition = object?.fields.find((candidate) => candidate.key === field)
    const defaultAllowed = object && definition ? !fieldRequiresExplicitAccess(object.config, definition.config) : false
    const previous = current.get(key) ?? { resource, field, visible: defaultAllowed, editable: defaultAllowed, masked: false }
    const next = { ...previous, ...patch }
    if (!next.visible) {
      next.editable = false
      next.masked = false
    }
    if (next.editable) next.visible = true
    setDraftPermissions((items) => [...items.filter((item) => `${item.resource}:${item.field}` !== key), next])
    setDirty(true)
  }

  if (!setup.data) return <PageQueryState title={t('fieldPerms.title')} description={t('fieldPerms.desc')} error={setup.error} onRetry={() => void setup.refetch()} />
  if (roleID && !configuration.data) return <PageQueryState title={t('fieldPerms.title')} description={t('fieldPerms.desc')} error={configuration.error} onRetry={() => void configuration.refetch()} />
  const data = setup.data

  return (
    <PageShell
      title={t('fieldPerms.title')}
      description={t('fieldPerms.desc')}
      actions={
        <Select value={roleID} onValueChange={setRoleID} disabled={dirty || publish.isPending}>
          <SelectTrigger className='w-52'><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectGroup>
              {data.roles.map((role) => <SelectItem key={role.id} value={role.id}>{role.name}</SelectItem>)}
            </SelectGroup>
          </SelectContent>
        </Select>
      }
    >
      <div className='mb-4 space-y-3 rounded-md border bg-muted/20 p-3'>
        <div>
          <p className='text-sm font-medium'>{t('roles.policyPublication.title')}</p>
          <p className='text-xs text-muted-foreground'>{t('roles.policyPublication.description')}</p>
        </div>
        <Textarea aria-label={t('roles.policyPublication.reason')} value={changeReason} onChange={(event) => setChangeReason(event.target.value)} placeholder={t('roles.policyPublication.reasonPlaceholder')} rows={2} />
        <div className='flex flex-wrap justify-end gap-2'>
          <Button variant='outline' disabled={!dirty || publish.isPending} onClick={() => { setDraftPermissions(configuration.data?.fieldPermissions ?? []); setDirty(false); setChangeReason('') }}>{t('scopes.discard')}</Button>
          <Button disabled={!dirty || publish.isPending || !changeReason.trim() || !configuration.data?.schemaHash} onClick={() => publish.mutate()}>{t('roles.policyPublication.publish')}</Button>
        </div>
      </div>
      <Tabs value={objectKey} onValueChange={setObjectKey}>
        <div className='max-w-full overflow-x-auto overscroll-x-contain'>
          <TabsList>
            {data.objects.map((object) => <TabsTrigger key={object.key} value={object.key}>{object.label || object.name || object.key}</TabsTrigger>)}
          </TabsList>
        </div>
        {data.objects.map((object) => (
          <TabsContent key={object.key} value={object.key}>
            {configuration.isPending ? <Skeleton className='h-64 w-full rounded-lg' /> : object.fields.length === 0 ? (
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
                      const requiresExplicitAccess = fieldRequiresExplicitAccess(object.config, field.config)
                      const visible = policy?.visible ?? !requiresExplicitAccess
                      const editable = policy?.editable ?? !requiresExplicitAccess
                      const masked = policy?.masked ?? false
                      return (
                        <TableRow key={field.key}>
                          <TableCell className='font-medium'>
                            <span className='flex items-center gap-2'>
                              {field.label || field.name || field.key}
                              {requiresExplicitAccess ? <Badge variant='outline'>{t('fieldPerms.sensitive')}</Badge> : null}
                            </span>
                          </TableCell>
                          <TableCell><code className='rounded bg-muted px-1.5 py-0.5 text-xs'>{field.key}</code></TableCell>
                          <TableCell><Switch aria-label={`${field.label || field.name || field.key} ${t('fieldPerms.table.visible')}`} data-field-permission-control={`${object.key}:${field.key}:visible`} checked={visible} disabled={publish.isPending} onCheckedChange={(value) => updateField(object.key, field.key, { visible: value })} /></TableCell>
                          <TableCell><Switch aria-label={`${field.label || field.name || field.key} ${t('fieldPerms.table.editable')}`} data-field-permission-control={`${object.key}:${field.key}:editable`} checked={editable} disabled={publish.isPending} onCheckedChange={(value) => updateField(object.key, field.key, { editable: value })} /></TableCell>
                          <TableCell><Switch aria-label={`${field.label || field.name || field.key} ${t('fieldPerms.table.masked')}`} data-field-permission-control={`${object.key}:${field.key}:masked`} checked={masked} disabled={publish.isPending} onCheckedChange={(value) => updateField(object.key, field.key, { masked: value })} /></TableCell>
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

function fieldRequiresExplicitAccess(objectConfig?: Record<string, unknown>, fieldConfig?: Record<string, unknown>) {
  if (String(objectConfig?.field_access_mode ?? '').trim() === 'default_deny') return true
  if (fieldConfig?.sensitive === true) return true
  return ['sensitive', 'secret', 'credential', 'security_raw', 'key_material'].includes(String(fieldConfig?.sensitivity ?? '').trim())
}
