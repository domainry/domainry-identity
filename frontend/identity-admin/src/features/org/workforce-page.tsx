import { useDeferredValue, useMemo, useState } from 'react'
import { Link } from '@tanstack/react-router'
import type { ColumnDef } from '@tanstack/react-table'
import {
  Badge,
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Field,
  FieldLabel,
  Input,
} from '@domainry/ui'
import { DataTable, DATA_TABLE_ACTION_CELL_CLASS, DATA_TABLE_ACTION_HEAD_CLASS, DATA_TABLE_TOOLBAR_CONTROL_CLASS } from '@/components/data-table'
import { PageShell } from '@/components/page-shell'
import { useOnboardWorkforce, useTerminateWorkforce, useWorkforceLifecycle, useWorkforceProfilesPage } from '@/data/hooks'
import type { WorkforceLifecycleOperation } from '@/data/api'
import type { WorkforceProfile } from '@/data/types'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { usePermissions } from '@/lib/permissions'

const WORKER_TYPE_LABELS = {
  employee: 'workforce.type.employee',
  contractor: 'workforce.type.contractor',
  partner_staff: 'workforce.type.partner_staff',
  temporary: 'workforce.type.temporary',
} as const satisfies Record<string, MessageKey>

const WORK_STATUS_LABELS = {
  pending: 'workforce.status.pending',
  active: 'workforce.status.active',
  suspended: 'workforce.status.suspended',
  terminated: 'workforce.status.terminated',
} as const satisfies Record<string, MessageKey>

type WorkforceOperation = WorkforceLifecycleOperation | 'terminate'

interface WorkforceDraft {
  accountName: string
  accountEmail: string
  accountPhone: string
  profileID: string
  identityUserID: string
  organizationID: string
  workerNo: string
  organizationUnitID: string
  assignmentID: string
  effectiveAt: string
  reason: string
  roleIDs: string
}

const EMPTY_DRAFT: WorkforceDraft = {
  accountName: '',
  accountEmail: '',
  accountPhone: '',
  profileID: '',
  identityUserID: '',
  organizationID: '',
  workerNo: '',
  organizationUnitID: '',
  assignmentID: '',
  effectiveAt: '',
  reason: '',
  roleIDs: '',
}

export function WorkforcePage() {
  const { t } = useI18n()
  const { has } = usePermissions()
  const lifecycle = useWorkforceLifecycle()
  const onboard = useOnboardWorkforce()
  const terminate = useTerminateWorkforce()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [sort, setSort] = useState<{ field: 'worker_no' | 'organization_id' | 'work_status' | 'start_date'; direction: 'asc' | 'desc' }>({ field: 'worker_no', direction: 'asc' })
  const deferredSearch = useDeferredValue(search)
  const workforce = useWorkforceProfilesPage({
    page,
    pageSize,
    search: deferredSearch,
    searchFields: ['worker_no', 'identity_user_id', 'organization_id'],
    filters: statusFilter ? { work_status: statusFilter } : undefined,
    sort: [sort, { field: 'id', direction: 'asc' }],
  })
  const [operation, setOperation] = useState<WorkforceOperation | null>(null)
  const [selected, setSelected] = useState<WorkforceProfile | null>(null)
  const [draft, setDraft] = useState<WorkforceDraft>(EMPTY_DRAFT)
  const [operationError, setOperationError] = useState('')
  const rows = workforce.data?.items ?? []
  const hasFilters = Boolean(search.trim() || statusFilter)
	const canOnboard = has('identity.workforce.onboard')
	const canLifecycle = has('identity.workforce.lifecycle')
	const canTerminate = has('identity.workforce.terminate')
  const busy = lifecycle.isPending || onboard.isPending || terminate.isPending
  const operationReady = Boolean(operation && draft.profileID.trim() && draft.reason.trim() && (
    operation !== 'invite'
    || (
      draft.accountName.trim()
      && draft.accountEmail.trim()
      && draft.identityUserID.trim()
      && draft.organizationID.trim()
      && draft.workerNo.trim()
      && draft.organizationUnitID.trim()
      && draft.effectiveAt
    )
  ) && (
    !['onboard', 'assign', 'transfer', 'add_secondary'].includes(operation)
    || (draft.organizationUnitID.trim() && draft.effectiveAt)
  ) && (
    operation !== 'transfer' || draft.assignmentID.trim()
  ) && (
    !['terminate', 'suspend'].includes(operation) || draft.effectiveAt
  ))
  const toggleSort = (field: typeof sort.field) => {
    setSort((current) => current.field === field ? { field, direction: current.direction === 'asc' ? 'desc' : 'asc' } : { field, direction: 'asc' })
    setPage(1)
  }
  const columns = useMemo<ColumnDef<WorkforceProfile, unknown>[]>(() => [
    {
      id: 'worker',
      accessorFn: (profile) => `${profile.workerNo} ${profile.identityUserId}`,
      header: () => <Button variant='ghost' size='sm' onClick={() => toggleSort('worker_no')}>{t('workforce.table.worker')}{sort.field === 'worker_no' ? ` ${sort.direction === 'asc' ? '↑' : '↓'}` : ''}</Button>,
      cell: ({ row }) => <div><Link to='/admin/org/workforce/$profileID' params={{ profileID: row.original.id }} className='font-medium hover:underline'>{row.original.workerNo}</Link><p className='text-xs text-muted-foreground'>{row.original.identityUserId}</p></div>,
    },
    {
      accessorKey: 'organizationId',
      header: () => <Button variant='ghost' size='sm' onClick={() => toggleSort('organization_id')}>{t('workforce.table.organization')}{sort.field === 'organization_id' ? ` ${sort.direction === 'asc' ? '↑' : '↓'}` : ''}</Button>,
    },
    { accessorKey: 'workerType', header: t('workforce.table.type'), cell: ({ row }) => t(WORKER_TYPE_LABELS[row.original.workerType]) },
    {
      accessorKey: 'workStatus',
      header: () => <Button variant='ghost' size='sm' onClick={() => toggleSort('work_status')}>{t('workforce.table.status')}{sort.field === 'work_status' ? ` ${sort.direction === 'asc' ? '↑' : '↓'}` : ''}</Button>,
      cell: ({ row }) => <Badge variant={row.original.workStatus === 'active' ? 'default' : 'secondary'}>{t(WORK_STATUS_LABELS[row.original.workStatus])}</Badge>,
    },
    {
      accessorKey: 'startDate',
      header: () => <Button variant='ghost' size='sm' onClick={() => toggleSort('start_date')}>{t('workforce.table.startDate')}{sort.field === 'start_date' ? ` ${sort.direction === 'asc' ? '↑' : '↓'}` : ''}</Button>,
      cell: ({ row }) => row.original.startDate || '—',
    },
    {
      id: 'actions',
      header: t('common.actions'),
      enableSorting: false,
      cell: ({ row }) => {
        const profile = row.original
        return <div className='flex flex-wrap justify-end gap-1'>
		  {profile.workStatus === 'pending' ? <Button size='sm' variant='outline' disabled={!canLifecycle || busy} onClick={() => openOperation('onboard', profile)}>{t('workforce.action.onboard')}</Button> : null}
		  {profile.workStatus === 'active' ? <>
			<Button size='sm' variant='outline' disabled={!canLifecycle || busy} onClick={() => openOperation('assign', profile)}>{t('workforce.action.assign')}</Button>
			<Button size='sm' variant='outline' disabled={!canLifecycle || busy} onClick={() => openOperation('transfer', profile)}>{t('workforce.action.transfer')}</Button>
			<Button size='sm' variant='outline' disabled={!canLifecycle || busy} onClick={() => openOperation('add_secondary', profile)}>{t('workforce.action.secondary')}</Button>
			<Button size='sm' variant='outline' disabled={!canLifecycle || busy} onClick={() => openOperation('suspend', profile)}>{t('workforce.action.suspend')}</Button>
			<Button size='sm' variant='outline' disabled={!canLifecycle || busy} onClick={() => openOperation('revoke_access', profile)}>{t('workforce.action.revokeAccess')}</Button>
			<Button size='sm' variant='destructive' disabled={!canTerminate || busy} onClick={() => openOperation('terminate', profile)}>{t('workforce.action.terminate')}</Button>
		  </> : null}
        </div>
      },
    },
	], [busy, canLifecycle, canTerminate, sort, t])

  function openOperation(next: WorkforceOperation, profile: WorkforceProfile | null = null) {
    setOperationError('')
    setSelected(profile)
    setOperation(next)
    setDraft({
      ...EMPTY_DRAFT,
      profileID: profile?.id ?? '',
      identityUserID: profile?.identityUserId ?? '',
      organizationID: profile?.organizationId ?? '',
      workerNo: profile?.workerNo ?? '',
      assignmentID: next === 'transfer' ? profile?.primaryAssignmentId ?? '' : '',
      effectiveAt: new Date().toISOString().slice(0, 10),
    })
  }

  async function submitOperation() {
    if (!operation || !draft.profileID.trim()) return
    if (operation === 'invite') {
      await onboard.mutateAsync({
        user: {
          id: draft.identityUserID.trim(),
          name: draft.accountName.trim(),
          email: draft.accountEmail.trim().toLowerCase(),
          phone: draft.accountPhone.trim() || undefined,
          status: 'active',
        },
        profile: {
          id: draft.profileID.trim(),
          organization_id: draft.organizationID.trim(),
          identity_user_id: draft.identityUserID.trim(),
          worker_no: draft.workerNo.trim(),
          worker_type: 'employee',
          work_status: 'active',
          start_date: draft.effectiveAt,
        },
        assignment: {
          id: draft.assignmentID.trim() || `assignment-${crypto.randomUUID()}`,
          organization_unit_id: draft.organizationUnitID.trim(),
          effective_from: draft.effectiveAt,
        },
        role_ids: draft.roleIDs.split(',').map((value) => value.trim()).filter(Boolean),
        reason: draft.reason.trim() || undefined,
      })
    } else if (operation === 'terminate') {
      await terminate.mutateAsync({
        profileID: draft.profileID.trim(),
        effectiveAt: draft.effectiveAt,
        reason: draft.reason,
      })
    } else {
      const profile = selected
      await lifecycle.mutateAsync({
        operation,
        profile: {
          id: draft.profileID.trim(),
          organization_id: draft.organizationID.trim(),
          identity_user_id: draft.identityUserID.trim(),
          worker_no: draft.workerNo.trim(),
          worker_type: profile?.workerType ?? 'employee',
          work_status: profile?.workStatus ?? 'pending',
          start_date: operation === 'onboard' ? draft.effectiveAt : profile?.startDate,
          end_date: profile?.endDate,
          primary_assignment_id: profile?.primaryAssignmentId,
          version: profile?.version,
        },
        assignment: ['onboard', 'assign', 'transfer', 'add_secondary'].includes(operation) ? {
          id: operation === 'transfer' || operation === 'onboard'
            ? `assignment-${crypto.randomUUID()}`
            : draft.assignmentID.trim() || `assignment-${crypto.randomUUID()}`,
          organization_unit_id: draft.organizationUnitID.trim(),
          assignment_type: operation === 'assign' ? 'temporary' : undefined,
          effective_from: draft.effectiveAt,
        } : undefined,
        previous_assignment_id: operation === 'transfer' ? draft.assignmentID.trim() : undefined,
        effective_at: draft.effectiveAt,
        reason: draft.reason,
      })
    }
    setOperation(null)
  }

  return (
    <PageShell
      title={t('workforce.title')}
      description={t('workforce.desc')}
	  actions={canOnboard ? <Button onClick={() => openOperation('invite')}>{t('workforce.action.invite')}</Button> : null}
    >
      <Card>
        <CardContent className='space-y-4 p-4'>
          <DataTable
            columns={columns}
            data={rows}
            getRowId={(profile) => profile.id}
            isLoading={workforce.isLoading}
            isRefreshing={workforce.isFetching && !workforce.isLoading}
            error={workforce.error}
            onRetry={() => void workforce.refetch()}
            search={{ value: search, onChange: (value) => { setSearch(value); setPage(1) }, fields: ['worker_no', 'identity_user_id', 'organization_id'], placeholder: t('workforce.searchPlaceholder') }}
            toolbarFilters={<Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-52`} value={statusFilter} onChange={(event) => { setStatusFilter(event.target.value.trim().toLowerCase()); setPage(1) }} placeholder={t('workforce.statusFilterPlaceholder')} aria-label={t('workforce.statusFilterPlaceholder')} />}
            hasActiveToolbarFilters={Boolean(statusFilter)}
            manualPagination={{ page, pageSize, total: workforce.data?.total ?? 0, onChange: (nextPage, nextPageSize) => { setPage(nextPageSize === pageSize ? nextPage : 1); setPageSize(nextPageSize) } }}
            pageSizeOptions={[20, 50, 100]}
            emptyTitle={t('workforce.empty.title')}
            emptyDescription={t('workforce.empty.desc')}
            filteredEmptyTitle={hasFilters ? t('workforce.filteredEmpty.title') : undefined}
            filteredEmptyDescription={hasFilters ? t('workforce.filteredEmpty.desc') : undefined}
            actionColumnId='actions'
            headClassName={{ actions: DATA_TABLE_ACTION_HEAD_CLASS }}
            cellClassName={{ actions: DATA_TABLE_ACTION_CELL_CLASS }}
          />
        </CardContent>
      </Card>
      <Dialog open={operation !== null} onOpenChange={(open) => { if (!open) { setOperation(null); setOperationError('') } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{operation ? t(`workforce.action.${operation === 'add_secondary' ? 'secondary' : operation}` as MessageKey) : ''}</DialogTitle>
            <DialogDescription>{t('workforce.operationDesc')}</DialogDescription>
          </DialogHeader>
          <div className='grid gap-4 sm:grid-cols-2'>
            {operation === 'invite' ? <>
              <Field><FieldLabel>{t('workforce.form.accountName')}</FieldLabel><Input value={draft.accountName} onChange={(event) => setDraft((value) => ({ ...value, accountName: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.accountEmail')}</FieldLabel><Input type='email' value={draft.accountEmail} onChange={(event) => setDraft((value) => ({ ...value, accountEmail: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.accountPhone')}</FieldLabel><Input value={draft.accountPhone} onChange={(event) => setDraft((value) => ({ ...value, accountPhone: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.profileID')}</FieldLabel><Input value={draft.profileID} onChange={(event) => setDraft((value) => ({ ...value, profileID: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.identityUserID')}</FieldLabel><Input value={draft.identityUserID} onChange={(event) => setDraft((value) => ({ ...value, identityUserID: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.organizationID')}</FieldLabel><Input value={draft.organizationID} onChange={(event) => setDraft((value) => ({ ...value, organizationID: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.workerNo')}</FieldLabel><Input value={draft.workerNo} onChange={(event) => setDraft((value) => ({ ...value, workerNo: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.organizationUnitID')}</FieldLabel><Input value={draft.organizationUnitID} onChange={(event) => setDraft((value) => ({ ...value, organizationUnitID: event.target.value }))} /></Field>
              <Field><FieldLabel>{t('workforce.form.assignmentID')}</FieldLabel><Input value={draft.assignmentID} onChange={(event) => setDraft((value) => ({ ...value, assignmentID: event.target.value }))} /></Field>
              <Field className='sm:col-span-2'><FieldLabel>{t('workforce.form.roleIDs')}</FieldLabel><Input value={draft.roleIDs} onChange={(event) => setDraft((value) => ({ ...value, roleIDs: event.target.value }))} placeholder={t('workforce.form.roleIDsPlaceholder')} /></Field>
            </> : null}
            {operation && ['onboard', 'assign', 'transfer', 'add_secondary'].includes(operation) ? <Field><FieldLabel>{t('workforce.form.organizationUnitID')}</FieldLabel><Input value={draft.organizationUnitID} onChange={(event) => setDraft((value) => ({ ...value, organizationUnitID: event.target.value }))} /></Field> : null}
            {operation && ['assign', 'transfer', 'add_secondary'].includes(operation) ? <Field><FieldLabel>{operation === 'transfer' ? t('workforce.form.previousAssignmentID') : t('workforce.form.assignmentID')}</FieldLabel><Input value={draft.assignmentID} onChange={(event) => setDraft((value) => ({ ...value, assignmentID: event.target.value }))} /></Field> : null}
            {operation !== 'revoke_access' ? <Field><FieldLabel>{t('workforce.form.effectiveAt')}</FieldLabel><Input type='date' value={draft.effectiveAt} onChange={(event) => setDraft((value) => ({ ...value, effectiveAt: event.target.value }))} /></Field> : null}
            <Field className='sm:col-span-2'><FieldLabel>{t('workforce.form.reason')}</FieldLabel><Input value={draft.reason} onChange={(event) => setDraft((value) => ({ ...value, reason: event.target.value }))} /></Field>
            {operationError ? <Alert variant='destructive' className='sm:col-span-2'>
              <AlertTitle>{t('workforce.operationFailed')}</AlertTitle>
              <AlertDescription>{operationError}</AlertDescription>
            </Alert> : null}
          </div>
          <DialogFooter>
            <Button variant='outline' onClick={() => setOperation(null)}>{t('common.cancel')}</Button>
            <Button
              disabled={busy || !operationReady}
              onClick={() => {
                setOperationError('')
                void submitOperation().catch((error: unknown) => {
                  setOperationError(error instanceof Error ? error.message : t('workforce.operationFailed'))
                })
              }}
            >
              {t('common.save')}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageShell>
  )
}
