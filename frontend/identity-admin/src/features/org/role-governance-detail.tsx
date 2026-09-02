import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Badge, Card, CardContent, CardHeader, CardTitle, Skeleton } from '@domainry/ui'
import { identityAccessApi, permissionsApi, type IdentityRoleGovernanceDetail } from '@/data/api'
import { displayText } from '@/data/text'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'

interface RoleGovernanceDetailProps {
  roleID: string
}

function ValueList({ values, empty }: { values: string[]; empty: string }) {
  if (!values.length) return <span className='text-sm text-muted-foreground'>{empty}</span>
  return <div className='flex flex-wrap gap-1.5'>{values.map((value) => <Badge key={value} variant='outline'>{value}</Badge>)}</div>
}

function GovernanceSection({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <Card className={cn('min-w-0 shadow-none', className)}>
      <CardHeader className='pb-2'><CardTitle className='text-sm'>{title}</CardTitle></CardHeader>
      <CardContent className='space-y-2 text-sm'>{children}</CardContent>
    </Card>
  )
}

function detailPermissionKeys(detail: IdentityRoleGovernanceDetail): string[] {
  return [...new Set(detail.permissions.map((item) => item.permission_key))].sort()
}

export function RoleGovernanceDetail({ roleID }: RoleGovernanceDetailProps) {
  const { t } = useI18n()
  const detailQuery = useQuery({
    queryKey: ['runtime', 'identity', 'role-governance-detail', roleID],
    queryFn: () => identityAccessApi.roleGovernanceDetail(roleID),
  })
  const versionsQuery = useQuery({
    queryKey: ['runtime', 'identity', 'role-versions', roleID],
    queryFn: () => identityAccessApi.roleVersions(roleID),
  })
  const permissionCatalogQuery = useQuery({
    queryKey: ['runtime', 'identity', 'permission-catalog'],
    queryFn: permissionsApi.catalog,
  })
  const impactQuery = useQuery({
    queryKey: ['runtime', 'identity', 'role-impact', roleID, detailQuery.data?.definition],
    queryFn: () => identityAccessApi.roleImpact(roleID, detailQuery.data!.definition),
    enabled: Boolean(detailQuery.data),
  })
  const permissionGroups = useMemo(() => {
    const granted = new Set(detailQuery.data ? detailPermissionKeys(detailQuery.data) : [])
    const points = (permissionCatalogQuery.data ?? []).filter((point) => granted.has(point.key))
    return {
      actions: points.filter((point) => point.source_type === 'business_action').map((point) => point.key).sort(),
      objects: points.filter((point) => point.source_type !== 'business_action').map((point) => point.key).sort(),
      unresolved: [...granted].filter((key) => !points.some((point) => point.key === key)).sort(),
    }
  }, [detailQuery.data, permissionCatalogQuery.data])

  if (detailQuery.isPending) {
    return <div className='grid gap-3 md:grid-cols-2' aria-label={t('roles.detail.loading')}>{[0, 1, 2, 3].map((item) => <Skeleton key={item} className='h-40 w-full' />)}</div>
  }
  if (detailQuery.isError) {
    return <p role='alert' className='text-sm text-destructive'>{t('roles.detail.loadFailed')}</p>
  }

  const detail = detailQuery.data
  const definition = detail.definition
  const permissionSetGroups = detail.permission_set_groups ?? []
  const permissionSets = detail.permission_sets ?? []
  const guardrails = detail.guardrails ?? []
  const dataScopes = detail.data_scopes ?? []
  const fieldPermissions = detail.field_permissions ?? []
  const exportRules = detail.export_rules ?? []
  const menus = detail.menus ?? []
  const members = detail.members ?? []
  const versions = versionsQuery.data?.items ?? []
  const impact = impactQuery.data
  return (
    <div className='grid gap-3 md:grid-cols-2' data-testid='role-governance-detail'>
      <GovernanceSection title={t('roles.detail.identity')}>
        <dl className='grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1'>
          <dt className='text-muted-foreground'>{t('roles.detail.roleKey')}</dt><dd><code>{detail.role.key}</code></dd>
          <dt className='text-muted-foreground'>{t('common.status')}</dt><dd>{detail.role.status}</dd>
          <dt className='text-muted-foreground'>{t('roles.detail.audience')}</dt><dd>{definition.audience || 'any'}</dd>
          <dt className='text-muted-foreground'>{t('roles.detail.binding')}</dt><dd>{definition.required_binding_key || '—'}</dd>
          <dt className='text-muted-foreground'>{t('roles.detail.assignmentMode')}</dt><dd>{definition.assignment_mode || 'manual'}</dd>
          <dt className='text-muted-foreground'>{t('roles.detail.risk')}</dt><dd>{definition.risk_level || 'normal'}</dd>
        </dl>
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.permissionSets')}>
        {permissionSetGroups.map((group) => <div key={group.key}><p className='font-medium'>{group.name || group.key}</p><ValueList values={group.permission_set_keys ?? []} empty={t('common.none')} /></div>)}
        {permissionSets.map((set) => <div key={set.key}><p className='font-medium'>{set.name || set.key}</p><ValueList values={set.permissions ?? []} empty={t('common.none')} /></div>)}
        {!permissionSetGroups.length && !permissionSets.length ? <span className='text-muted-foreground'>{t('common.none')}</span> : null}
        {guardrails.length ? <div><p className='font-medium'>{t('roles.detail.guardrails')}</p><ValueList values={guardrails.map((item) => item.key)} empty={t('common.none')} /></div> : null}
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.businessActions')}>
        <ValueList values={permissionGroups.actions} empty={t('common.none')} />
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.objectCapabilities')}>
        <ValueList values={[...permissionGroups.objects, ...permissionGroups.unresolved]} empty={t('common.none')} />
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.dataScopes')}>
        {dataScopes.length ? dataScopes.map((scope) => <div key={`${scope.resource}:${scope.scope}`} className='flex justify-between gap-3'><code>{scope.resource}</code><span>{scope.scope}{scope.audit_denial ? ` · ${t('roles.detail.auditDenial')}` : ''}</span></div>) : <span className='text-muted-foreground'>{t('common.none')}</span>}
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.fieldExport')}>
        {fieldPermissions.map((field) => <div key={`${field.resource}:${field.field}`}><code>{field.resource}.{field.field}</code> · {field.visible ? t('roles.detail.read') : t('roles.detail.noRead')} · {field.editable ? t('roles.detail.write') : t('roles.detail.noWrite')}{field.masked ? ` · ${t('roles.detail.masked')}` : ''}</div>)}
        {exportRules.map((rule) => <div key={`${rule.object_key}:${rule.mode}`}><code>{rule.object_key}</code> · {t('roles.detail.export')} {rule.mode} · {(rule.fields ?? []).join(', ') || t('common.none')}</div>)}
        {!fieldPermissions.length && !exportRules.length ? <span className='text-muted-foreground'>{t('common.none')}</span> : null}
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.menuEntrypoints')} className='md:col-span-2'>
        {menus.length ? (
          <div className='overflow-hidden rounded-lg border bg-muted/10' data-testid='role-menu-entrypoints'>
            <div className='hidden grid-cols-[minmax(0,1.1fr)_minmax(10rem,.8fr)_minmax(0,1.4fr)] gap-5 border-b bg-muted/40 px-4 py-2 text-xs font-medium text-muted-foreground md:grid'>
              <span>{t('roles.detail.menuName')}</span>
              <span>{t('roles.detail.menuKey')}</span>
              <span>{t('roles.detail.entrypoint')}</span>
            </div>
            <div className='divide-y'>
              {menus.map((menu) => (
                <div
                  key={menu.id}
                  className='grid gap-3 px-4 py-3 md:grid-cols-[minmax(0,1.1fr)_minmax(10rem,.8fr)_minmax(0,1.4fr)] md:items-center md:gap-5'
                >
                  <div className='min-w-0'>
                    <span className='mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground md:hidden'>{t('roles.detail.menuName')}</span>
                    <span className='font-medium leading-5'>{displayText(t, menu.label)}</span>
                  </div>
                  <div className='min-w-0'>
                    <span className='mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground md:hidden'>{t('roles.detail.menuKey')}</span>
                    <code className='block break-all text-xs text-muted-foreground'>{menu.key}</code>
                  </div>
                  <div className='min-w-0'>
                    <span className='mb-1 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground md:hidden'>{t('roles.detail.entrypoint')}</span>
                    <div className='flex min-w-0 flex-wrap items-center gap-2'>
                      <code className='min-w-0 break-all text-xs text-muted-foreground'>
                        {menu.route || t('roles.detail.menuGroup')}
                      </code>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : <span className='text-muted-foreground'>{t('common.none')}</span>}
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.membersSources')}>
        {members.length ? members.map((member) => <div key={`${member.user_id}:${member.profile_id ?? ''}`}><code>{member.user_id}</code> · {member.assignment_source || member.source || 'direct'}{member.binding_key ? ` · ${member.binding_key}:${member.profile_id}` : ''}</div>) : <span className='text-muted-foreground'>{t('common.none')}</span>}
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.conflictsImpact')}>
        <p>{t('roles.detail.conflicts')}</p><ValueList values={definition.conflict_role_keys ?? []} empty={t('common.none')} />
        {impactQuery.isPending ? <Skeleton className='h-10 w-full' /> : impact ? <dl className='grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1'>
          <dt className='text-muted-foreground'>{t('roles.detail.affectedUsers')}</dt><dd>{impact.affected_user_count}</dd>
          <dt className='text-muted-foreground'>{t('roles.detail.affectedObjects')}</dt><dd>{(impact.affected_objects ?? []).join(', ') || t('common.none')}</dd>
          <dt className='text-muted-foreground'>{t('roles.detail.highRisk')}</dt><dd>{(impact.high_risk_capabilities ?? []).join(', ') || t('common.none')}</dd>
        </dl> : <span className='text-muted-foreground'>{t('roles.detail.impactUnavailable')}</span>}
      </GovernanceSection>

      <GovernanceSection title={t('roles.detail.versionsAudit')}>
        {versionsQuery.isPending ? <Skeleton className='h-10 w-full' /> : versions.length ? versions.map((version) => <div key={version.id}><p className='font-medium'>{version.event}</p><p className='text-xs text-muted-foreground'>{version.created_at} · {version.actor_id} · {version.summary}</p></div>) : <span className='text-muted-foreground'>{t('common.none')}</span>}
      </GovernanceSection>
    </div>
  )
}
