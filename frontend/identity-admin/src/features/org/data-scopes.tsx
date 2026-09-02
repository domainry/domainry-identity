import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
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
  platformCapabilitiesApi,
  rolesApi,
  type RuntimeDataScopePolicy,
} from '@/data/api'
import { useI18n, type MessageKey } from '@/lib/i18n'
import {
  dataScopeValues,
  effectiveObjectScope,
  isDataScopeOptionDisabled,
} from './data-scopes-view-model'

type ScopeType = string

const SCOPE_LABEL_KEYS: Record<string, MessageKey> = {
  all_records: 'scopes.type.all',
  organization_and_children: 'scopes.type.organizationTree',
  organization: 'scopes.type.organization',
  owned_records: 'scopes.type.self',
  custom: 'scopes.type.custom',
  none: 'scopes.type.none',
}

type RoleDraft = {
  items: RuntimeDataScopePolicy[]
  schemaHash: string
}

export function DataScopesPage() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [roleFilter, setRoleFilter] = useState('')
  const [drafts, setDrafts] = useState<Record<string, RoleDraft>>({})
  const [dirtyRoles, setDirtyRoles] = useState<Set<string>>(new Set())
  const [changeReason, setChangeReason] = useState('')
  const query = useQuery({
    queryKey: ['runtime', 'identity', 'data-scopes'],
    queryFn: async () => {
      const [roles, schema, capabilities] = await Promise.all([
        rolesApi.list(),
        objectsApi.schemaSnapshot(),
        platformCapabilitiesApi.get(),
      ])
      const policies = await Promise.all(roles.map(async (role) => ({
        role,
        configuration: await identityPoliciesApi.dataScopeConfiguration(role.id),
      })))
      return {
        roles,
        objects: (schema.objects ?? []).filter((object) => object.config?.system_object !== true),
        scopeValues: authoringParameter(capabilities, 'identity.role_data_scope', 'data_scope')?.enum ?? [],
        policies,
      }
    },
  })

  useEffect(() => {
    if (!query.data || dirtyRoles.size) return
    setDrafts(Object.fromEntries(query.data.policies.map(({ role, configuration }) => [role.id, {
      items: configuration.dataScopes,
      schemaHash: configuration.schemaHash,
    }])))
  }, [dirtyRoles.size, query.data])
  useEffect(() => {
    if (!roleFilter && query.data?.roles[0]) setRoleFilter(query.data.roles[0].id)
  }, [query.data, roleFilter])

  const publish = useMutation({
    mutationFn: async () => {
      if (!query.data || !changeReason.trim()) throw new Error('role-policy-publication-not-ready')
      const [roleID] = [...dirtyRoles]
      const draft = drafts[roleID]
      if (dirtyRoles.size !== 1 || !draft?.schemaHash) throw new Error('role-policy-revision-not-ready')
      return {
        roleID,
        configuration: await identityPoliciesApi.saveDataScopes(roleID, draft.items, changeReason.trim(), draft.schemaHash),
      }
    },
    onSuccess: async ({ roleID, configuration }) => {
      setDrafts((current) => {
        const next = { ...current }
        next[roleID] = { items: configuration.dataScopes, schemaHash: configuration.schemaHash }
        return next
      })
      setDirtyRoles(new Set())
      setChangeReason('')
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['runtime', 'identity', 'data-scopes'] }),
        queryClient.invalidateQueries({ queryKey: ['runtime', 'permissions', 'effective'] }),
      ])
      toast.success(t('roles.policyPublication.toast.published'))
    },
    onError: () => toast.error(t('roles.policyPublication.toast.failed')),
  })

  const rows = useMemo(() => {
    if (!query.data) return []
    return query.data.policies.flatMap(({ role, configuration }) => {
      const draft = drafts[role.id] ?? { items: configuration.dataScopes, schemaHash: configuration.schemaHash }
      return query.data.objects.map((object) => ({
        role,
        object,
        scope: effectiveObjectScope(draft.items.find((item) => item.resource === object.key)?.scope ?? ('none' as const)),
        policies: draft.items,
      }))
    })
  }, [drafts, query.data])
  const visible = rows.filter((row) => row.role.id === roleFilter)

  function setScope(roleID: string, objectKey: string, scope: ScopeType) {
    const source = drafts[roleID]
    if (!source) return
    setDrafts((current) => ({
      ...current,
      [roleID]: {
        ...source,
        items: scope === 'none'
          ? source.items.filter((item) => item.resource !== objectKey)
          : [...source.items.filter((item) => item.resource !== objectKey), { resource: objectKey, scope }],
      },
    }))
    setDirtyRoles((current) => new Set(current).add(roleID))
  }

  function discard() {
    if (!query.data) return
    setDrafts(Object.fromEntries(query.data.policies.map(({ role, configuration }) => [role.id, {
      items: configuration.dataScopes,
      schemaHash: configuration.schemaHash,
    }])))
    setDirtyRoles(new Set())
    setChangeReason('')
  }

  if (!query.data) return <PageQueryState title={t('scopes.title')} description={t('scopes.desc')} error={query.error} onRetry={() => void query.refetch()} />
  const data = query.data
  const scopeValues = dataScopeValues(
    data.scopeValues,
    data.policies.flatMap(({ configuration }) => configuration.dataScopes.map((item) => item.scope)),
  )

  return (
    <PageShell title={t('scopes.title')} description={t('scopes.desc')}>
      <Card>
        <CardHeader className='gap-3 pb-3'>
          <div>
            <CardTitle className='text-base'>{t('scopes.matrixTitle')}</CardTitle>
            <CardDescription>{t('scopes.matrixDescription')}</CardDescription>
          </div>
          <Textarea aria-label={t('roles.policyPublication.reason')} value={changeReason} onChange={(event) => setChangeReason(event.target.value)} placeholder={t('roles.policyPublication.reasonPlaceholder')} rows={2} />
          <DataTableToolbar
            filters={<Select value={roleFilter} onValueChange={setRoleFilter} disabled={dirtyRoles.size > 0}>
              <SelectTrigger className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-52`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  {data.roles.map((role) => <SelectItem key={role.id} value={role.id}>{role.name}</SelectItem>)}
                </SelectGroup>
              </SelectContent>
            </Select>}
            actions={<>
              <span className='text-xs text-muted-foreground'>{t('common.count', { count: visible.length })}</span>
              <Button variant='outline' disabled={!dirtyRoles.size || publish.isPending} onClick={discard}>{t('scopes.discard')}</Button>
              <Button disabled={!dirtyRoles.size || publish.isPending || !changeReason.trim()} onClick={() => publish.mutate()}>{t('roles.policyPublication.publish')}</Button>
            </>}
          />
        </CardHeader>
        <CardContent className='flex flex-col gap-3'>
          <div className='max-w-full overflow-x-auto rounded-md border overscroll-x-contain [&>[data-slot=table-container]]:overflow-visible'>
            <Table className='min-w-[760px] table-fixed'>
              <TableHeader>
                <TableRow>
                  <TableHead className='sticky left-0 z-20 w-48 bg-background'>{t('scopes.table.role')}</TableHead>
                  <TableHead className='w-64'>{t('scopes.table.module')}</TableHead>
                  <TableHead className='w-64'>{t('scopes.table.scope')}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visible.map((row) => (
                  <TableRow key={`${row.role.id}:${row.object.key}`} className='group hover:bg-muted/50'>
                    <TableCell className='sticky left-0 z-10 bg-background group-hover:bg-muted'>
                      <Badge variant={dirtyRoles.has(row.role.id) ? 'default' : 'secondary'}>{row.role.name}</Badge>
                    </TableCell>
                    <TableCell className='font-medium'>{row.object.label || row.object.name || row.object.key}</TableCell>
                    <TableCell>
                      <Select value={row.scope} disabled={publish.isPending} onValueChange={(scope) => setScope(row.role.id, row.object.key, scope as ScopeType)}>
                        <SelectTrigger data-policy-control={`${row.role.id}:${row.object.key}:scope`} size='sm' className='w-48'><SelectValue /></SelectTrigger>
                        <SelectContent><SelectGroup>{scopeValues.map((scope) => (
                          <SelectItem key={scope} value={scope} disabled={isDataScopeOptionDisabled(scope, row.scope, row.policies, row.object.key)}>
                            {SCOPE_LABEL_KEYS[scope] ? t(SCOPE_LABEL_KEYS[scope]) : scope}
                          </SelectItem>
                        ))}</SelectGroup></SelectContent>
                      </Select>
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
