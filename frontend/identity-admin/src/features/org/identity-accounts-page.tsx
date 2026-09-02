import { useDeferredValue, useMemo, useState } from 'react'
import { Link } from '@tanstack/react-router'
import type { ColumnDef } from '@tanstack/react-table'
import { Check, Copy, Pencil, Plus, Power, Trash2 } from 'lucide-react'
import {
  Badge,
  Button,
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
} from '@domainry/ui'
import { DataTable, DataTableRowActions, DATA_TABLE_ACTION_CELL_CLASS, DATA_TABLE_ACTION_HEAD_CLASS, DATA_TABLE_TOOLBAR_CONTROL_CLASS } from '@/components/data-table'
import { DestructiveConfirmationDialog } from '@/components/destructive-confirmation-dialog'
import { PageShell } from '@/components/page-shell'
import { identityAccountsApi, type IdentityUserDeletionImpact } from '@/data/api'
import { displayText } from '@/data/text'
import {
  useCreateIdentityAccount,
  useDeleteIdentityAccount,
  useIdentityAccounts,
  useIdentityAccountsPage,
  useOrganizationUnits,
  useUpdateIdentityAccount,
} from '@/data/hooks'
import type { IdentityAccount } from '@/data/types'
import { useI18n } from '@/lib/i18n'
import { usePermissions } from '@/lib/permissions'
import { AccountDisableDialog } from './account-disable-dialog'

type AccountDraft = Pick<IdentityAccount, 'name' | 'givenName' | 'middleName' | 'familyName' | 'namePrefix' | 'nameSuffix' | 'nativeName' | 'nameLocale' | 'email' | 'phone' | 'accountType' | 'locale' | 'timezone' | 'organizationUnitId' | 'supportOrganizationUnitId' | 'managerUserId' | 'workerNo' | 'workerType' | 'workStatus' | 'startDate' | 'endDate' | 'status'>

const EMPTY_ACCOUNT: AccountDraft = {
  name: '',
  givenName: '',
  middleName: '',
  familyName: '',
  namePrefix: '',
  nameSuffix: '',
  nativeName: '',
  nameLocale: '',
  email: '',
  phone: '',
  accountType: 'human',
  locale: '',
  timezone: '',
  organizationUnitId: '',
  supportOrganizationUnitId: '',
  managerUserId: '',
  workerNo: '',
  workerType: 'employee',
  workStatus: 'active',
  startDate: '',
  endDate: '',
  status: 'active',
}

export function IdentityAccountsPage() {
  const { t } = useI18n()
  const { has } = usePermissions()
  const create = useCreateIdentityAccount()
  const update = useUpdateIdentityAccount()
  const remove = useDeleteIdentityAccount()
  const { data: organizationUnits = [] } = useOrganizationUnits()
  const { data: accountOptions = [] } = useIdentityAccounts()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [sort, setSort] = useState<{ field: 'name' | 'email' | 'status'; direction: 'asc' | 'desc' }>({ field: 'name', direction: 'asc' })
  const deferredSearch = useDeferredValue(search)
  const accounts = useIdentityAccountsPage({
    page,
    pageSize,
    search: deferredSearch,
    searchFields: ['name', 'email', 'phone'],
    filters: statusFilter ? { status: statusFilter } : undefined,
    sort: [sort, { field: 'id', direction: 'asc' }],
  })
  const [editing, setEditing] = useState<IdentityAccount | null | undefined>(undefined)
  const [draft, setDraft] = useState<AccountDraft>(EMPTY_ACCOUNT)
  const [deleting, setDeleting] = useState<IdentityAccount | null>(null)
  const [impact, setImpact] = useState<IdentityUserDeletionImpact | null>(null)
  const [impactPending, setImpactPending] = useState(false)
  const [disabling, setDisabling] = useState<IdentityAccount | null>(null)
  const [restoring, setRestoring] = useState<IdentityAccount | null>(null)
  const [initialCredential, setInitialCredential] = useState<{ login: string; password: string } | null>(null)
  const [credentialCopied, setCredentialCopied] = useState(false)
  const rows = accounts.data?.items ?? []
  const accountTotal = accounts.data
    ? Math.max(
        accounts.data.total,
        (page - 1) * pageSize + rows.length + (accounts.data.has_next ? 1 : 0)
      )
    : 0
  const hasFilters = Boolean(search.trim() || statusFilter)
  const busy = create.isPending || update.isPending || remove.isPending
  const toggleSort = (field: 'name' | 'email' | 'status') => {
    setSort((current) => current.field === field ? { field, direction: current.direction === 'asc' ? 'desc' : 'asc' } : { field, direction: 'asc' })
    setPage(1)
  }
  const columns = useMemo<ColumnDef<IdentityAccount, unknown>[]>(() => [
    {
      id: 'account',
      accessorFn: (account) => `${account.name} ${account.email}`,
      header: () => <Button variant='ghost' size='sm' onClick={() => toggleSort('name')}>{t('accounts.table.account')}{sort.field === 'name' ? ` ${sort.direction === 'asc' ? '↑' : '↓'}` : ''}</Button>,
      cell: ({ row }) => <div><Link to='/admin/security/accounts/$userId' params={{ userId: row.original.id }} className='font-medium hover:underline'>{displayText(t, row.original.name)}</Link><p className='text-xs text-muted-foreground'>{row.original.email}</p></div>,
    },
    { accessorKey: 'phone', header: t('accounts.table.phone'), cell: ({ row }) => row.original.phone || '—' },
    {
      id: 'status',
      accessorKey: 'status',
      header: () => <Button variant='ghost' size='sm' onClick={() => toggleSort('status')}>{t('accounts.table.status')}{sort.field === 'status' ? ` ${sort.direction === 'asc' ? '↑' : '↓'}` : ''}</Button>,
      cell: ({ row }) => <Badge variant={row.original.status === 'active' ? 'default' : 'secondary'}>{row.original.status === 'active' ? t('common.enabled') : t('common.disabled')}</Badge>,
    },
    {
      id: 'actions',
      header: t('common.actions'),
      enableSorting: false,
      cell: ({ row }) => <DataTableRowActions
        menuLabel={t('common.actions')}
        primary={[
		  { label: t('common.edit'), icon: Pencil, disabled: !has('identity.users.update') || busy, onSelect: () => openEdit(row.original) },
		  { label: row.original.status === 'active' ? t('common.disable') : t('common.enable'), icon: Power, disabled: !has(row.original.status === 'active' ? 'identity.users.disable' : 'identity.users.enable') || busy, onSelect: () => row.original.status === 'active' ? setDisabling(row.original) : setRestoring(row.original) },
        ]}
		secondary={[{ label: t('common.delete'), icon: Trash2, destructive: true, disabled: !has('identity.users.delete') || busy, onSelect: () => void previewDelete(row.original) }]}
      />,
    },
	  ], [busy, has, sort, t, update])

  function openCreate() {
    setEditing(null)
    setDraft(EMPTY_ACCOUNT)
  }

  function openEdit(account: IdentityAccount) {
    setEditing(account)
    setDraft({
      name: account.name,
      givenName: account.givenName,
      middleName: account.middleName,
      familyName: account.familyName,
      namePrefix: account.namePrefix,
      nameSuffix: account.nameSuffix,
      nativeName: account.nativeName,
      nameLocale: account.nameLocale,
      email: account.email,
      phone: account.phone,
      accountType: account.accountType,
      locale: account.locale,
      timezone: account.timezone,
      organizationUnitId: account.organizationUnitId,
      supportOrganizationUnitId: account.supportOrganizationUnitId,
      managerUserId: account.managerUserId,
      workerNo: account.workerNo,
      workerType: account.workerType,
      workStatus: account.workStatus,
      startDate: account.startDate,
      endDate: account.endDate,
      status: account.status,
    })
  }

  async function save() {
    const normalized = {
      ...draft,
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
      locale: draft.locale.trim(),
      timezone: draft.timezone.trim(),
      organizationUnitId: draft.organizationUnitId.trim(),
      supportOrganizationUnitId: draft.supportOrganizationUnitId.trim(),
      managerUserId: draft.managerUserId.trim(),
      workerNo: draft.workerNo.trim(),
      startDate: draft.startDate.trim(),
      endDate: draft.endDate.trim(),
    }
    if (!normalized.name || !normalized.email) return
    if (editing) {
      await update.mutateAsync({ id: editing.id, patch: normalized })
    } else {
      const provisioned = await create.mutateAsync(normalized)
      setCredentialCopied(false)
      setInitialCredential({
        login: provisioned.account.email || provisioned.account.id,
        password: provisioned.initialPassword,
      })
    }
    setEditing(undefined)
  }

  async function copyInitialCredential() {
    if (!initialCredential) return
    await navigator.clipboard.writeText(initialCredential.password)
    setCredentialCopied(true)
  }

  function closeInitialCredential() {
    setInitialCredential(null)
    setCredentialCopied(false)
    create.reset()
  }

  async function previewDelete(account: IdentityAccount) {
    setDeleting(account)
    setImpact(null)
    setImpactPending(true)
    try {
      setImpact(await identityAccountsApi.deletionImpact(account.id))
    } finally {
      setImpactPending(false)
    }
  }

  async function confirmDelete() {
    if (!deleting || !impact?.can_delete) return
    await remove.mutateAsync(deleting.id)
    setDeleting(null)
    setImpact(null)
  }

  return (
    <PageShell
      title={t('accounts.title')}
      description={t('accounts.desc')}
	  actions={has('identity.users.create') ? <Button onClick={openCreate}><Plus className='size-4' />{t('accounts.new')}</Button> : null}
    >
      <DataTable
        columns={columns}
        data={rows}
        getRowId={(account) => account.id}
        isLoading={accounts.isLoading}
        isRefreshing={accounts.isFetching && !accounts.isLoading}
        error={accounts.error}
        onRetry={() => void accounts.refetch()}
        search={{ value: search, onChange: (value) => { setSearch(value); setPage(1) }, fields: ['name', 'email', 'phone'], placeholder: t('accounts.searchPlaceholder') }}
        toolbarFilters={<Select value={statusFilter || '__all__'} onValueChange={(value) => { setStatusFilter(value === '__all__' ? '' : value); setPage(1) }}><SelectTrigger className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('accounts.statusFilterPlaceholder')}><SelectValue /></SelectTrigger><SelectContent><SelectItem value='__all__'>{t('common.all')}</SelectItem><SelectItem value='active'>{t('common.enabled')}</SelectItem><SelectItem value='disabled'>{t('common.disabled')}</SelectItem></SelectContent></Select>}
        hasActiveToolbarFilters={Boolean(statusFilter)}
        manualPagination={{ page, pageSize, total: accountTotal, onChange: (nextPage, nextPageSize) => { setPage(nextPage); setPageSize(nextPageSize) } }}
        pageSizeOptions={[10, 20, 50, 100]}
        emptyTitle={t('accounts.emptyTitle')}
        emptyDescription={t('accounts.emptyDescription')}
        filteredEmptyTitle={hasFilters ? t('accounts.filteredEmptyTitle') : undefined}
        filteredEmptyDescription={hasFilters ? t('accounts.filteredEmptyDescription') : undefined}
		emptyAction={has('identity.users.create') ? <Button onClick={openCreate}><Plus />{t('accounts.new')}</Button> : undefined}
        actionColumnId='actions'
        headClassName={{ actions: DATA_TABLE_ACTION_HEAD_CLASS }}
        cellClassName={{ actions: DATA_TABLE_ACTION_CELL_CLASS }}
      />
      <Dialog open={editing !== undefined} onOpenChange={(open) => { if (!open) setEditing(undefined) }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{editing ? t('accounts.edit') : t('accounts.new')}</DialogTitle>
            <DialogDescription>{t('accounts.dialogDesc')}</DialogDescription>
          </DialogHeader>
          <div className='grid gap-4 sm:grid-cols-2'>
            <Field className='sm:col-span-2'><FieldLabel htmlFor='account-name'>{t('accounts.form.name')}</FieldLabel><Input id='account-name' value={String(draft.name)} onChange={(event) => setDraft((value) => ({ ...value, name: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-given-name'>{t('accounts.form.givenName')}</FieldLabel><Input id='account-given-name' value={draft.givenName} onChange={(event) => setDraft((value) => ({ ...value, givenName: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-middle-name'>{t('accounts.form.middleName')}</FieldLabel><Input id='account-middle-name' value={draft.middleName} onChange={(event) => setDraft((value) => ({ ...value, middleName: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-family-name'>{t('accounts.form.familyName')}</FieldLabel><Input id='account-family-name' value={draft.familyName} onChange={(event) => setDraft((value) => ({ ...value, familyName: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-native-name'>{t('accounts.form.nativeName')}</FieldLabel><Input id='account-native-name' value={draft.nativeName} onChange={(event) => setDraft((value) => ({ ...value, nativeName: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-name-prefix'>{t('accounts.form.namePrefix')}</FieldLabel><Input id='account-name-prefix' value={draft.namePrefix} onChange={(event) => setDraft((value) => ({ ...value, namePrefix: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-name-suffix'>{t('accounts.form.nameSuffix')}</FieldLabel><Input id='account-name-suffix' value={draft.nameSuffix} onChange={(event) => setDraft((value) => ({ ...value, nameSuffix: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-name-locale'>{t('accounts.form.nameLocale')}</FieldLabel><Input id='account-name-locale' value={draft.nameLocale} placeholder='en-US' onChange={(event) => setDraft((value) => ({ ...value, nameLocale: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-email'>{t('accounts.form.email')}</FieldLabel><Input id='account-email' type='email' value={draft.email} onChange={(event) => setDraft((value) => ({ ...value, email: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-phone'>{t('accounts.form.phone')}</FieldLabel><Input id='account-phone' value={draft.phone} onChange={(event) => setDraft((value) => ({ ...value, phone: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-type'>{t('accounts.form.accountType')}</FieldLabel><Select value={draft.accountType} onValueChange={(accountType) => setDraft((value) => ({ ...value, accountType: accountType as IdentityAccount['accountType'] }))}><SelectTrigger id='account-type'><SelectValue /></SelectTrigger><SelectContent><SelectItem value='human'>{t('accounts.accountType.human')}</SelectItem><SelectItem value='service'>{t('accounts.accountType.service')}</SelectItem><SelectItem value='automation'>{t('accounts.accountType.automation')}</SelectItem></SelectContent></Select></Field>
            <Field><FieldLabel htmlFor='account-locale'>{t('accounts.form.locale')}</FieldLabel><Input id='account-locale' value={draft.locale} placeholder='en-US' onChange={(event) => setDraft((value) => ({ ...value, locale: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-timezone'>{t('accounts.form.timezone')}</FieldLabel><Input id='account-timezone' value={draft.timezone} placeholder='America/New_York' onChange={(event) => setDraft((value) => ({ ...value, timezone: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-organization-unit'>{t('accounts.form.organizationUnit')}</FieldLabel><Select value={draft.organizationUnitId || '__none__'} onValueChange={(value) => setDraft((draftValue) => ({ ...draftValue, organizationUnitId: value === '__none__' ? '' : value }))}><SelectTrigger id='account-organization-unit'><SelectValue /></SelectTrigger><SelectContent><SelectItem value='__none__'>{t('common.none')}</SelectItem>{organizationUnits.map((unit) => <SelectItem key={unit.id} value={unit.id}>{displayText(t, unit.name)} · {t(`organizationUnit.nodeType.${unit.nodeType}`)}</SelectItem>)}</SelectContent></Select></Field>
            <Field><FieldLabel htmlFor='account-support-organization-unit'>{t('accounts.form.supportOrganizationUnit')}</FieldLabel><Select value={draft.supportOrganizationUnitId || '__none__'} onValueChange={(value) => setDraft((draftValue) => ({ ...draftValue, supportOrganizationUnitId: value === '__none__' ? '' : value }))}><SelectTrigger id='account-support-organization-unit'><SelectValue /></SelectTrigger><SelectContent><SelectItem value='__none__'>{t('common.none')}</SelectItem>{organizationUnits.filter((unit) => unit.status === 'active').map((unit) => <SelectItem key={unit.id} value={unit.id}>{displayText(t, unit.name)} · {t(`organizationUnit.nodeType.${unit.nodeType}`)}</SelectItem>)}</SelectContent></Select></Field>
            <Field><FieldLabel htmlFor='account-manager'>{t('accounts.form.manager')}</FieldLabel><Select value={draft.managerUserId || '__none__'} onValueChange={(value) => setDraft((draftValue) => ({ ...draftValue, managerUserId: value === '__none__' ? '' : value }))}><SelectTrigger id='account-manager'><SelectValue /></SelectTrigger><SelectContent><SelectItem value='__none__'>{t('common.none')}</SelectItem>{accountOptions.map((account) => account.id === editing?.id ? null : <SelectItem key={account.id} value={account.id}>{displayText(t, account.name)} · {account.email}</SelectItem>)}</SelectContent></Select></Field>
            <Field><FieldLabel htmlFor='account-worker-no'>{t('accounts.form.workerNo')}</FieldLabel><Input id='account-worker-no' value={draft.workerNo} onChange={(event) => setDraft((value) => ({ ...value, workerNo: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-worker-type'>{t('accounts.form.workerType')}</FieldLabel><Select value={draft.workerType || '__none__'} onValueChange={(value) => setDraft((draftValue) => ({ ...draftValue, workerType: value === '__none__' ? '' : value as IdentityAccount['workerType'] }))}><SelectTrigger id='account-worker-type'><SelectValue /></SelectTrigger><SelectContent><SelectItem value='__none__'>{t('common.none')}</SelectItem>{(['employee', 'contractor', 'partner_staff', 'temporary'] as const).map((type) => <SelectItem key={type} value={type}>{t(`accounts.workerType.${type}`)}</SelectItem>)}</SelectContent></Select></Field>
            <Field><FieldLabel htmlFor='account-work-status'>{t('accounts.form.workStatus')}</FieldLabel><Select value={draft.workStatus || '__none__'} onValueChange={(value) => setDraft((draftValue) => ({ ...draftValue, workStatus: value === '__none__' ? '' : value as IdentityAccount['workStatus'] }))}><SelectTrigger id='account-work-status'><SelectValue /></SelectTrigger><SelectContent><SelectItem value='__none__'>{t('common.none')}</SelectItem>{(['pending', 'active', 'suspended', 'terminated'] as const).map((status) => <SelectItem key={status} value={status}>{t(`accounts.workStatus.${status}`)}</SelectItem>)}</SelectContent></Select></Field>
            <Field><FieldLabel htmlFor='account-start-date'>{t('accounts.form.startDate')}</FieldLabel><Input id='account-start-date' type='date' value={draft.startDate} onChange={(event) => setDraft((value) => ({ ...value, startDate: event.target.value }))} /></Field>
            <Field><FieldLabel htmlFor='account-end-date'>{t('accounts.form.endDate')}</FieldLabel><Input id='account-end-date' type='date' value={draft.endDate} onChange={(event) => setDraft((value) => ({ ...value, endDate: event.target.value }))} /></Field>
          </div>
          <DialogFooter><Button variant='outline' onClick={() => setEditing(undefined)}>{t('common.cancel')}</Button><Button disabled={busy || !String(draft.name).trim() || !draft.email.trim()} onClick={() => void save()}>{t('common.save')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={Boolean(initialCredential)} onOpenChange={(open) => { if (!open) closeInitialCredential() }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t('accounts.initialCredentialTitle')}</DialogTitle>
            <DialogDescription>{t('accounts.initialCredentialDesc')}</DialogDescription>
          </DialogHeader>
          {initialCredential ? <div className='space-y-4'>
            <Field>
              <FieldLabel htmlFor='account-initial-login'>{t('accounts.initialLogin')}</FieldLabel>
              <Input id='account-initial-login' value={initialCredential.login} readOnly />
            </Field>
            <Field>
              <FieldLabel htmlFor='account-initial-password'>{t('accounts.defaultPassword')}</FieldLabel>
              <div className='flex gap-2'>
                <Input id='account-initial-password' value={initialCredential.password} readOnly className='font-mono' />
                <Button variant='outline' size='icon' aria-label={t('accounts.copyInitialPassword')} onClick={() => void copyInitialCredential()}>
                  {credentialCopied ? <Check className='size-4' /> : <Copy className='size-4' />}
                </Button>
              </div>
            </Field>
            <p className='text-sm font-medium text-destructive'>{t('accounts.initialCredentialOneTimeWarning')}</p>
          </div> : null}
          <DialogFooter><Button onClick={closeInitialCredential}>{t('accounts.initialCredentialDone')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
      <DestructiveConfirmationDialog
        open={Boolean(deleting)}
        title={t('accounts.deleteTitle')}
        description={t('accounts.deleteDesc')}
        confirmLabel={t('common.delete')}
        cancelLabel={t('common.cancel')}
        pending={remove.isPending}
        confirmDisabled={impactPending || !impact?.can_delete}
        onOpenChange={(open) => { if (!open) { setDeleting(null); setImpact(null) } }}
        onConfirm={() => void confirmDelete()}
      >
          {impactPending ? <p className='text-sm text-muted-foreground'>{t('accounts.impactLoading')}</p> : null}
          {impact ? <div className='space-y-3 rounded-lg border p-4 text-sm'>
            <p>{t('accounts.impactProfiles', { count: impact.profile_bindings.length })}</p>
            {impact.profile_bindings.map((binding) => <code key={`${binding.object_key}:${binding.profile_id}`} className='block rounded bg-muted px-2 py-1'>{binding.object_key}:{binding.profile_id}</code>)}
            <p>{t('accounts.impactRoles', { count: impact.active_role_ids.length })}</p>
            <p>{t('accounts.impactBusinessRecords', { count: impact.business_profile_references.reduce((total, reference) => total + reference.count, 0) })}</p>
            <p>{t('accounts.impactOwnedRecords', { count: impact.owned_record_references.reduce((total, reference) => total + reference.count, 0) })}</p>
            <p>{t('accounts.impactApprovalTasks', { count: impact.pending_approval_task_ids.length })}</p>
            <p>{t('accounts.impactAuditRetention', { count: impact.retained_audit_event_ids.length })}</p>
            <p>{t('accounts.impactLegalHolds', { count: impact.active_legal_hold_ids.length })}</p>
            <p>{t('accounts.impactSessions')}</p>
            {!impact.can_delete ? <p className='font-medium text-destructive'>{t('accounts.deleteBlocked', { blockers: impact.blockers.join(', ') })}</p> : null}
          </div> : null}
      </DestructiveConfirmationDialog>
      <AccountDisableDialog account={disabling} onClose={() => setDisabling(null)} />
      <DestructiveConfirmationDialog
        open={Boolean(restoring)}
        title={t('common.enableTitle', { name: restoring ? displayText(t, restoring.name) : '' })}
        description={t('common.enableDescription')}
        confirmLabel={t('common.enable')}
        cancelLabel={t('common.cancel')}
        pending={update.isPending}
        destructive={false}
        onOpenChange={(open) => { if (!open) setRestoring(null) }}
        onConfirm={() => restoring && update.mutate({ id: restoring.id, patch: { status: 'active' } }, { onSuccess: () => setRestoring(null) })}
      />
    </PageShell>
  )
}
