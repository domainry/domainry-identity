import { useState } from 'react'
import { Link, useNavigate } from '@tanstack/react-router'
import { ArrowLeft, KeyRound, LockOpen, LogOut, Pencil, Power } from 'lucide-react'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Field,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Skeleton,
} from '@domainry/ui'
import { PageShell } from '@/components/page-shell'
import { DetailConflictAlert, DetailPageState, isDetailConflictError } from '@/components/detail-page-state'
import { DestructiveConfirmationDialog } from '@/components/destructive-confirmation-dialog'
import { identityAccountsApi } from '@/data/api'
import { displayText } from '@/data/text'
import { useIdentityAccount, useIdentityAccountSecurity, useUpdateIdentityAccount } from '@/data/hooks'
import type { IdentityAccount } from '@/data/types'
import { useI18n } from '@/lib/i18n'
import { usePermissions } from '@/lib/permissions'
import { AccountDisableDialog } from './account-disable-dialog'
import { EffectiveAccessExplainCard } from './effective-access-explain-card'
import { IdentityRoleAssignmentList } from './identity-role-assignment-list'

function AccountField({ label, value }: { label: string; value: string }) {
  return <div><dt className='text-xs text-muted-foreground'>{label}</dt><dd className='mt-1 break-words text-sm font-medium'>{value || '—'}</dd></div>
}

function securityTime(value?: string) {
  return value || '—'
}

export function IdentityUserDetailPage({ userID }: { userID: string }) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const { has } = usePermissions()
  const account = useIdentityAccount(userID)
  const security = useIdentityAccountSecurity(userID)
  const update = useUpdateIdentityAccount()
  const [editing, setEditing] = useState(false)
  const [resettingPassword, setResettingPassword] = useState(false)
  const [newPassword, setNewPassword] = useState('')
  const [passwordPending, setPasswordPending] = useState(false)
  const [disableOpen, setDisableOpen] = useState(false)
  const [restoreOpen, setRestoreOpen] = useState(false)
  const [securityActionPending, setSecurityActionPending] = useState<'unlock' | 'force_logout' | ''>('')
  const [mutationResult, setMutationResult] = useState<{ message: string; error?: boolean } | null>(null)
  const [detailConflict, setDetailConflict] = useState<Error | null>(null)
  const [draft, setDraft] = useState<Pick<IdentityAccount, 'name' | 'givenName' | 'middleName' | 'familyName' | 'namePrefix' | 'nameSuffix' | 'nativeName' | 'nameLocale' | 'email' | 'phone' | 'accountType' | 'locale' | 'timezone'>>({
    name: '', givenName: '', middleName: '', familyName: '', namePrefix: '', nameSuffix: '', nativeName: '', nameLocale: '', email: '', phone: '', accountType: 'human', locale: '', timezone: '',
  })
  const backToAccounts = () => void navigate({ to: '/admin/security/accounts' })
  if (account.isPending) return <DetailPageState title={t('accounts.title')} />
  if (!account.data || account.isError) return <DetailPageState title={t('accounts.title')} error={account.error} kind={!account.error ? 'not-found' : undefined} onRetry={() => void account.refetch()} onBack={backToAccounts} backLabel={t('personDetail.back')} />
  const value = account.data
  const openEdit = () => {
    setDraft({
      name: value.name,
      givenName: value.givenName,
      middleName: value.middleName,
      familyName: value.familyName,
      namePrefix: value.namePrefix,
      nameSuffix: value.nameSuffix,
      nativeName: value.nativeName,
      nameLocale: value.nameLocale,
      email: value.email,
      phone: value.phone,
      accountType: value.accountType,
      locale: value.locale,
      timezone: value.timezone,
    })
    setEditing(true)
  }
  const save = async () => {
    setMutationResult(null)
    try {
      await update.mutateAsync({
        id: value.id,
        patch: {
          expectedResourceHash: value.resourceHash,
          name: String(draft.name).trim(),
          givenName: draft.givenName.trim(),
          middleName: draft.middleName.trim(),
          familyName: draft.familyName.trim(),
          namePrefix: draft.namePrefix.trim(),
          nameSuffix: draft.nameSuffix.trim(),
          nativeName: draft.nativeName.trim(),
          nameLocale: draft.nameLocale.trim(),
          email: draft.email.trim().toLowerCase(),
          phone: draft.phone.trim(),
          accountType: draft.accountType,
          locale: draft.locale.trim(),
          timezone: draft.timezone.trim(),
        },
      })
      setDetailConflict(null)
      setEditing(false)
    } catch (error) {
      if (isDetailConflictError(error)) {
        setDetailConflict(error instanceof Error ? error : new Error('detail conflict'))
      } else {
        setMutationResult({ message: error instanceof Error ? error.message : t('dataTable.errorDescription'), error: true })
      }
    }
  }
  const reloadLatestAccount = async () => {
    const refreshed = await account.refetch()
    if (refreshed.data) {
      setDetailConflict(null)
      setEditing(false)
    }
  }
  const refreshSecurity = async () => {
    const refreshed = await security.refetch()
    return !refreshed.isError
  }
  const resetPassword = async () => {
    setPasswordPending(true)
    setMutationResult(null)
    try {
      const result = await identityAccountsApi.resetPassword(value.id, newPassword)
      if (!result.ok) throw new Error('password reset was not accepted')
      const refreshed = await refreshSecurity()
      setMutationResult(refreshed
        ? { message: t('accounts.resetPasswordResult') }
        : { message: t('accounts.mutationCompletedRefreshFailed'), error: true })
      setResettingPassword(false)
      setNewPassword('')
    } catch {
      setMutationResult({ message: t('dataTable.errorDescription'), error: true })
    } finally {
      setPasswordPending(false)
    }
  }
  const unlock = async () => {
    setSecurityActionPending('unlock')
    setMutationResult(null)
    try {
      const result = await identityAccountsApi.unlock(value.id)
      const refreshed = await refreshSecurity()
      setMutationResult(refreshed
        ? { message: t('accounts.unlockResult', { status: result.status }) }
        : { message: t('accounts.mutationCompletedRefreshFailed'), error: true })
    } catch {
      setMutationResult({ message: t('dataTable.errorDescription'), error: true })
    } finally {
      setSecurityActionPending('')
    }
  }
  const forceLogout = async () => {
    setSecurityActionPending('force_logout')
    setMutationResult(null)
    try {
      const result = await identityAccountsApi.forceLogout(value.id)
      const refreshed = await refreshSecurity()
      setMutationResult(refreshed
        ? { message: t('accounts.forceLogoutResult', { count: result.revoked_sessions }) }
        : { message: t('accounts.mutationCompletedRefreshFailed'), error: true })
    } catch {
      setMutationResult({ message: t('dataTable.errorDescription'), error: true })
    } finally {
      setSecurityActionPending('')
    }
  }
  return <PageShell
    title={displayText(t, value.name)}
    description={t('accounts.detailDesc')}
    actions={<div className='flex flex-wrap gap-2'>
      <Button asChild variant='outline'><Link to='/admin/security/accounts'><ArrowLeft className='size-4' />{t('personDetail.back')}</Link></Button>
	  {has('identity.users.update') ? <Button variant='outline' onClick={openEdit}><Pencil className='size-4' />{t('common.edit')}</Button> : null}
	  {has('auth.reset_password') ? <Button variant='outline' onClick={() => setResettingPassword(true)}><KeyRound className='size-4' />{t('accounts.resetPassword')}</Button> : null}
	  {has('identity.users.unlock') && security.data?.locked ? <Button variant='outline' disabled={Boolean(securityActionPending)} onClick={() => void unlock()}><LockOpen className='size-4' />{t('accounts.unlock')}</Button> : null}
	  {has('identity.users.force_logout') ? <Button variant='outline' disabled={Boolean(securityActionPending)} onClick={() => void forceLogout()}><LogOut className='size-4' />{t('accounts.forceLogout')}</Button> : null}
	  {has(value.status === 'active' ? 'identity.users.disable' : 'identity.users.enable') ? <Button variant={value.status === 'active' ? 'outline' : 'default'} disabled={update.isPending} onClick={() => value.status === 'active' ? setDisableOpen(true) : setRestoreOpen(true)}><Power className='size-4' />{value.status === 'active' ? t('common.disable') : t('common.enable')}</Button> : null}
    </div>}
  >
    {detailConflict && !editing ? <DetailConflictAlert error={detailConflict} onReload={() => void reloadLatestAccount()} /> : null}
    {mutationResult ? <Card role={mutationResult.error ? 'alert' : 'status'}><CardContent className={`p-4 text-sm font-medium ${mutationResult.error ? 'text-destructive' : 'text-primary'}`}>{mutationResult.message}</CardContent></Card> : null}
    <Card>
      <CardHeader><CardTitle>{t('accounts.securitySubject')}</CardTitle></CardHeader>
      <CardContent>
        <dl className='grid gap-5 md:grid-cols-2 xl:grid-cols-3'>
          <AccountField label={t('accounts.form.name')} value={displayText(t, value.name)} />
          <AccountField label={t('accounts.form.givenName')} value={value.givenName} />
          <AccountField label={t('accounts.form.middleName')} value={value.middleName} />
          <AccountField label={t('accounts.form.familyName')} value={value.familyName} />
          <AccountField label={t('accounts.form.nativeName')} value={value.nativeName} />
          <AccountField label={t('accounts.form.namePrefix')} value={value.namePrefix} />
          <AccountField label={t('accounts.form.nameSuffix')} value={value.nameSuffix} />
          <AccountField label={t('accounts.form.nameLocale')} value={value.nameLocale} />
          <AccountField label={t('accounts.form.email')} value={value.email} />
          <AccountField label={t('accounts.form.phone')} value={value.phone} />
          <AccountField label={t('accounts.form.accountType')} value={t(`accounts.accountType.${value.accountType}`)} />
          <AccountField label={t('accounts.form.locale')} value={value.locale} />
          <AccountField label={t('accounts.form.timezone')} value={value.timezone} />
          <AccountField label={t('accounts.version')} value={String(value.version)} />
          <AccountField label={t('accounts.createdAt')} value={value.createdAt} />
          <AccountField label={t('accounts.updatedAt')} value={value.updatedAt} />
          <AccountField label={t('accounts.accountId')} value={value.id} />
          <div><dt className='text-xs text-muted-foreground'>{t('accounts.table.status')}</dt><dd className='mt-1'><Badge variant={value.status === 'active' ? 'default' : 'secondary'}>{value.status === 'active' ? t('common.enabled') : t('common.disabled')}</Badge></dd></div>
        </dl>
      </CardContent>
    </Card>
	{has('identity.user_role_assignments.list') ? <IdentityRoleAssignmentList userID={value.id} /> : null}
    <Card>
      <CardHeader><CardTitle>{t('accounts.securityPosture')}</CardTitle></CardHeader>
      <CardContent>
        {security.isPending ? <Skeleton className='h-24 w-full' /> : security.isError || !security.data ? <p className='text-sm text-destructive'>{t('dataTable.errorDescription')}</p> : (
          <dl className='grid gap-5 md:grid-cols-2 xl:grid-cols-4'>
            <AccountField label={t('accounts.mfaStatus')} value={security.data.mfa_enabled ? t('common.enabled') : t('common.disabled')} />
            <AccountField label={t('accounts.lockStatus')} value={security.data.locked ? t('accounts.locked') : t('accounts.unlocked')} />
            <AccountField label={t('accounts.activeSessions')} value={String(security.data.active_sessions)} />
            <AccountField label={t('accounts.lastLogin')} value={securityTime(security.data.credential?.last_login_at)} />
            <AccountField label={t('accounts.lockedUntil')} value={securityTime(security.data.credential?.locked_until)} />
            <AccountField label={t('accounts.failedLoginCount')} value={String(security.data.credential?.failed_login_count ?? 0)} />
            <AccountField label={t('accounts.passwordUpdatedAt')} value={securityTime(security.data.credential?.password_updated_at)} />
            <AccountField label={t('accounts.mustChangePassword')} value={security.data.credential?.must_change_password ? t('common.yes') : t('common.no')} />
          </dl>
        )}
      </CardContent>
    </Card>
    {security.data ? (
      <div className='grid min-w-0 gap-4 xl:grid-cols-3'>
        <Card>
          <CardHeader><CardTitle>{t('accounts.mfaFactors')}</CardTitle></CardHeader>
          <CardContent className='space-y-2'>{security.data.mfa_factors.map((factor) => <div key={factor.id} className='rounded-md border p-3 text-sm'><p className='font-medium'>{factor.label || factor.type}</p><p className='text-muted-foreground'>{factor.provider || factor.type} · {factor.status} · {securityTime(factor.last_used_at)}</p></div>)}{security.data.mfa_factors.length === 0 ? <p className='text-sm text-muted-foreground'>{t('common.emptyTitle')}</p> : null}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>{t('accounts.sessions')}</CardTitle></CardHeader>
          <CardContent className='min-w-0 space-y-2'>{security.data.sessions.map((session) => <div key={session.id} className='min-w-0 overflow-hidden rounded-md border p-3 text-sm'><p className='break-all font-mono text-xs font-medium'>{session.session_id || session.id}</p><p className='break-words text-muted-foreground'>{t('accounts.sessionExpires')} {securityTime(session.expires_at)} · {session.revoked_at ? t('accounts.sessionRevoked') : t('accounts.sessionActive')}</p></div>)}{security.data.sessions.length === 0 ? <p className='text-sm text-muted-foreground'>{t('common.emptyTitle')}</p> : null}</CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle>{t('accounts.externalAccounts')}</CardTitle></CardHeader>
          <CardContent className='space-y-2'>{security.data.external_accounts.map((external) => <div key={external.id} className='rounded-md border p-3 text-sm'><p className='font-medium'>{external.provider}</p><p className='text-muted-foreground'>{external.display_name || external.email || external.phone || external.id}</p></div>)}{security.data.external_accounts.length === 0 ? <p className='text-sm text-muted-foreground'>{t('common.emptyTitle')}</p> : null}</CardContent>
        </Card>
      </div>
    ) : null}
	{has('identity.access.explain') ? <EffectiveAccessExplainCard userID={value.id} /> : null}
    <Card>
      <CardContent className='p-5 text-sm text-muted-foreground'>{t('accounts.separateDirectories')}</CardContent>
    </Card>
    <Dialog open={editing} onOpenChange={setEditing}>
      <DialogContent>
        <DialogHeader><DialogTitle>{t('accounts.edit')}</DialogTitle><DialogDescription>{t('accounts.dialogDesc')}</DialogDescription></DialogHeader>
        {detailConflict ? <DetailConflictAlert error={detailConflict} onReload={() => void reloadLatestAccount()} /> : null}
        <div className='grid gap-4 sm:grid-cols-2'>
          <Field className='sm:col-span-2'><FieldLabel>{t('accounts.form.name')}</FieldLabel><Input value={String(draft.name)} onChange={(event) => setDraft((current) => ({ ...current, name: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.givenName')}</FieldLabel><Input value={draft.givenName} onChange={(event) => setDraft((current) => ({ ...current, givenName: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.middleName')}</FieldLabel><Input value={draft.middleName} onChange={(event) => setDraft((current) => ({ ...current, middleName: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.familyName')}</FieldLabel><Input value={draft.familyName} onChange={(event) => setDraft((current) => ({ ...current, familyName: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.nativeName')}</FieldLabel><Input value={draft.nativeName} onChange={(event) => setDraft((current) => ({ ...current, nativeName: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.namePrefix')}</FieldLabel><Input value={draft.namePrefix} onChange={(event) => setDraft((current) => ({ ...current, namePrefix: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.nameSuffix')}</FieldLabel><Input value={draft.nameSuffix} onChange={(event) => setDraft((current) => ({ ...current, nameSuffix: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.nameLocale')}</FieldLabel><Input value={draft.nameLocale} placeholder='en-US' onChange={(event) => setDraft((current) => ({ ...current, nameLocale: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.email')}</FieldLabel><Input type='email' value={draft.email} onChange={(event) => setDraft((current) => ({ ...current, email: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.phone')}</FieldLabel><Input value={draft.phone} onChange={(event) => setDraft((current) => ({ ...current, phone: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.accountType')}</FieldLabel><Select value={draft.accountType} onValueChange={(accountType) => setDraft((current) => ({ ...current, accountType: accountType as IdentityAccount['accountType'] }))}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value='human'>{t('accounts.accountType.human')}</SelectItem><SelectItem value='service'>{t('accounts.accountType.service')}</SelectItem><SelectItem value='automation'>{t('accounts.accountType.automation')}</SelectItem></SelectContent></Select></Field>
          <Field><FieldLabel>{t('accounts.form.locale')}</FieldLabel><Input value={draft.locale} placeholder='en-US' onChange={(event) => setDraft((current) => ({ ...current, locale: event.target.value }))} /></Field>
          <Field><FieldLabel>{t('accounts.form.timezone')}</FieldLabel><Input value={draft.timezone} placeholder='America/New_York' onChange={(event) => setDraft((current) => ({ ...current, timezone: event.target.value }))} /></Field>
        </div>
        <DialogFooter><Button variant='outline' onClick={() => setEditing(false)}>{t('common.cancel')}</Button><Button disabled={update.isPending || !String(draft.name).trim() || !draft.email.trim()} onClick={() => void save()}>{t('common.save')}</Button></DialogFooter>
      </DialogContent>
    </Dialog>
    <Dialog open={resettingPassword} onOpenChange={setResettingPassword}>
      <DialogContent>
        <DialogHeader><DialogTitle>{t('accounts.resetPassword')}</DialogTitle><DialogDescription>{t('accounts.resetPasswordDesc')}</DialogDescription></DialogHeader>
        <Field><FieldLabel>{t('accounts.newPassword')}</FieldLabel><Input type='password' autoComplete='new-password' value={newPassword} onChange={(event) => setNewPassword(event.target.value)} /></Field>
        <DialogFooter><Button variant='outline' onClick={() => setResettingPassword(false)}>{t('common.cancel')}</Button><Button disabled={passwordPending || newPassword.length < 12} onClick={() => void resetPassword()}>{t('accounts.resetPassword')}</Button></DialogFooter>
      </DialogContent>
    </Dialog>
    <AccountDisableDialog account={disableOpen ? value : null} onClose={() => setDisableOpen(false)} />
    <DestructiveConfirmationDialog
      open={restoreOpen}
      title={t('common.enableTitle', { name: displayText(t, value.name) })}
      description={t('common.enableDescription')}
      confirmLabel={t('common.enable')}
      cancelLabel={t('common.cancel')}
      pending={update.isPending}
      destructive={false}
      onOpenChange={setRestoreOpen}
      onConfirm={() => update.mutate({ id: value.id, patch: { status: 'active' } }, { onSuccess: () => setRestoreOpen(false) })}
    />
  </PageShell>
}
