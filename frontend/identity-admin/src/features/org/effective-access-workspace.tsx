import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Badge,
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
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from '@domainry/ui'
import { PageQueryState } from '@/components/page-query-state'
import { identityAccessApi, identityAccountsApi, type IdentityGrantSource } from '@/data/api'
import { useI18n } from '@/lib/i18n'

function sourceLabel(source: IdentityGrantSource) {
  return [
    source.type,
    source.role_key || source.role_id,
    source.permission_set_key,
    source.binding_key,
    source.assignment_source,
  ].filter(Boolean).join(':')
}

function Sources({ sources }: { sources: IdentityGrantSource[] }) {
  const { t } = useI18n()
  if (!sources.length) return <span className='text-muted-foreground'>{t('common.none')}</span>
  return (
    <div className='flex flex-wrap gap-1'>
      {sources.map((source, index) => (
        <Badge key={`${source.key}:${index}`} variant='outline'>{sourceLabel(source) || source.key}</Badge>
      ))}
    </div>
  )
}

export function EffectiveAccessWorkspace() {
  const { t } = useI18n()
  const [userID, setUserID] = useState('')
  const [roleKey, setRoleKey] = useState('')
  const [objectAction, setObjectAction] = useState('')
  const accounts = useQuery({ queryKey: ['runtime', 'identity', 'accounts', 'effective-access'], queryFn: identityAccountsApi.list })
  const reverse = useQuery({ queryKey: ['runtime', 'identity', 'access-reverse-index'], queryFn: identityAccessApi.reverseIndex })
  useEffect(() => {
    if (!userID && accounts.data?.[0]) setUserID(accounts.data[0].id)
  }, [accounts.data, userID])
  const snapshot = useQuery({
    queryKey: ['runtime', 'identity', 'effective-access', userID],
    queryFn: () => identityAccessApi.snapshot(userID),
    enabled: Boolean(userID),
  })
  const roles = useMemo(() => Object.keys(reverse.data?.role_permissions ?? {}).sort(), [reverse.data])
  const objectActions = useMemo(() => Object.keys(reverse.data?.object_action_roles ?? {}).sort(), [reverse.data])
  useEffect(() => {
    if (!roleKey && roles[0]) setRoleKey(roles[0])
  }, [roleKey, roles])
  useEffect(() => {
    if (!objectAction && objectActions[0]) setObjectAction(objectActions[0])
  }, [objectAction, objectActions])

  if (accounts.isError || reverse.isError) {
    return <PageQueryState title={t('effectiveAccess.title')} description={t('effectiveAccess.desc')} error={accounts.error ?? reverse.error} onRetry={() => { void accounts.refetch(); void reverse.refetch() }} />
  }

  return (
    <div className='space-y-4 p-4 md:p-5'>
      <div>
        <h2 className='text-xl font-semibold'>{t('effectiveAccess.title')}</h2>
        <p className='mt-1 text-sm text-muted-foreground'>{t('effectiveAccess.desc')}</p>
      </div>
      <Tabs defaultValue='user'>
        <TabsList aria-label={t('effectiveAccess.directions')}>
          <TabsTrigger value='user'>{t('effectiveAccess.byUser')}</TabsTrigger>
          <TabsTrigger value='role'>{t('effectiveAccess.byRole')}</TabsTrigger>
          <TabsTrigger value='object-action'>{t('effectiveAccess.byObjectAction')}</TabsTrigger>
        </TabsList>
        <TabsContent value='user' className='mt-4 space-y-4'>
          <Select value={userID} onValueChange={setUserID}>
            <SelectTrigger className='w-full max-w-sm'><SelectValue placeholder={t('effectiveAccess.selectUser')} /></SelectTrigger>
            <SelectContent><SelectGroup>{(accounts.data ?? []).map((account) => <SelectItem key={account.id} value={account.id}>{account.name} · {account.email}</SelectItem>)}</SelectGroup></SelectContent>
          </Select>
          <Card>
            <CardHeader>
              <CardTitle>{t('effectiveAccess.effectivePermissions')}</CardTitle>
              <CardDescription>{t('effectiveAccess.revision', { revision: snapshot.data?.authorization_revision || '-' })}</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader><TableRow><TableHead>{t('effectiveAccess.permission')}</TableHead><TableHead>{t('effectiveAccess.target')}</TableHead><TableHead>{t('effectiveAccess.sources')}</TableHead></TableRow></TableHeader>
                <TableBody>
                  {(snapshot.data?.permissions ?? []).map((permission) => (
                    <TableRow key={permission.key}>
                      <TableCell><code>{permission.key}</code></TableCell>
                      <TableCell>{[permission.object_key, permission.action].filter(Boolean).join(' / ') || '-'}</TableCell>
                      <TableCell><Sources sources={permission.sources} /></TableCell>
                    </TableRow>
                  ))}
                  {snapshot.data && snapshot.data.permissions.length === 0 ? <TableRow><TableCell colSpan={3} className='text-center text-muted-foreground'>{t('common.none')}</TableCell></TableRow> : null}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value='role' className='mt-4 space-y-4'>
          <Select value={roleKey} onValueChange={setRoleKey}>
            <SelectTrigger className='w-full max-w-sm'><SelectValue placeholder={t('effectiveAccess.selectRole')} /></SelectTrigger>
            <SelectContent><SelectGroup>{roles.map((role) => <SelectItem key={role} value={role}>{role}</SelectItem>)}</SelectGroup></SelectContent>
          </Select>
          <Card><CardContent className='pt-6'><Table>
            <TableHeader><TableRow><TableHead>{t('effectiveAccess.permission')}</TableHead><TableHead>{t('effectiveAccess.sources')}</TableHead></TableRow></TableHeader>
            <TableBody>{(reverse.data?.role_permissions[roleKey] ?? []).map((permission) => <TableRow key={permission}><TableCell><code>{permission}</code></TableCell><TableCell><Badge variant='outline'>role:{roleKey}</Badge></TableCell></TableRow>)}</TableBody>
          </Table></CardContent></Card>
        </TabsContent>
        <TabsContent value='object-action' className='mt-4 space-y-4'>
          <Select value={objectAction} onValueChange={setObjectAction}>
            <SelectTrigger className='w-full max-w-sm'><SelectValue placeholder={t('effectiveAccess.selectObjectAction')} /></SelectTrigger>
            <SelectContent><SelectGroup>{objectActions.map((key) => <SelectItem key={key} value={key}>{key}</SelectItem>)}</SelectGroup></SelectContent>
          </Select>
          <Card><CardContent className='pt-6'><Table>
            <TableHeader><TableRow><TableHead>{t('effectiveAccess.role')}</TableHead><TableHead>{t('effectiveAccess.sources')}</TableHead></TableRow></TableHeader>
            <TableBody>{(reverse.data?.object_action_roles[objectAction] ?? []).map((role) => <TableRow key={role}><TableCell><code>{role}</code></TableCell><TableCell><Badge variant='outline'>role:{role}</Badge></TableCell></TableRow>)}</TableBody>
          </Table></CardContent></Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
