import { useDeferredValue, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { Plus } from 'lucide-react'
import { toast } from 'sonner'
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
} from '@domainry/ui'
import { DataTable, DATA_TABLE_TOOLBAR_CONTROL_CLASS } from '@/components/data-table'
import { useIdentityRoleAssignmentsPage } from '@/data/hooks'
import { identityAccountsApi, rolesApi, type RuntimeRoleAssignment } from '@/data/api'
import { useI18n } from '@/lib/i18n'
import { usePermissions } from '@/lib/permissions'

type AssignmentSortField = 'role_id' | 'source' | 'status' | 'created_at'

export function IdentityRoleAssignmentList({ userID }: { userID: string }) {
  const { t } = useI18n()
  const { has } = usePermissions()
  const queryClient = useQueryClient()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(10)
  const [search, setSearch] = useState('')
  const [status, setStatus] = useState('')
  const [sort, setSort] = useState<{ field: AssignmentSortField; direction: 'asc' | 'desc' }>({ field: 'created_at', direction: 'desc' })
  const [assignOpen, setAssignOpen] = useState(false)
  const [roleID, setRoleID] = useState('')
  const [reason, setReason] = useState('')
  const deferredSearch = useDeferredValue(search)
  const assignments = useIdentityRoleAssignmentsPage(userID, {
    page,
    pageSize,
    search: deferredSearch,
    searchFields: ['role_id', 'source', 'granted_by'],
    filters: status ? { status } : undefined,
    sort: [sort, { field: 'role_id', direction: 'asc' }],
  })
  const roles = useQuery({
    queryKey: ['runtime', 'identity', 'roles', 'assignment-options'],
    queryFn: rolesApi.list,
    enabled: assignOpen,
  })
  const assign = useMutation({
    mutationFn: () => identityAccountsApi.assignRole(userID, roleID, reason.trim()),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['runtime', 'identity', 'users', userID, 'role-assignments'] }),
      ])
      setAssignOpen(false)
      setRoleID('')
      setReason('')
      toast.success(t('roleAssignments.assignSuccess'))
    },
    onError: () => toast.error(t('roleAssignments.assignFailed')),
  })
  const toggleSort = (field: AssignmentSortField) => {
    setSort((current) => current.field === field ? { field, direction: current.direction === 'asc' ? 'desc' : 'asc' } : { field, direction: 'asc' })
    setPage(1)
  }
  const heading = (field: AssignmentSortField, label: string) => (
    <Button variant='ghost' size='sm' onClick={() => toggleSort(field)}>
      {label}{sort.field === field ? ` ${sort.direction === 'asc' ? '↑' : '↓'}` : ''}
    </Button>
  )
  const columns = useMemo<ColumnDef<RuntimeRoleAssignment, unknown>[]>(() => [
    { accessorKey: 'role_id', header: () => heading('role_id', t('roleAssignments.role')), cell: ({ row }) => <span className='font-medium'>{row.original.role_id}</span> },
    { accessorKey: 'source', header: () => heading('source', t('roleAssignments.source')), cell: ({ row }) => row.original.source || '—' },
    { accessorKey: 'status', header: () => heading('status', t('roleAssignments.status')), cell: ({ row }) => <Badge variant={row.original.status === 'active' ? 'default' : 'secondary'}>{row.original.status || 'active'}</Badge> },
    { id: 'validity', header: t('roleAssignments.validity'), cell: ({ row }) => <>{row.original.valid_from || '—'} – {row.original.valid_until || '—'}</> },
    { accessorKey: 'created_at', header: () => heading('created_at', t('roleAssignments.createdAt')), cell: ({ row }) => row.original.created_at || '—' },
  ], [sort, t])

  return <Card>
    <CardHeader className='flex-row items-center justify-between gap-3'>
      <CardTitle>{t('roleAssignments.title')}</CardTitle>
	  {has('identity.user_role_assignments.assign') ? <Button size='sm' onClick={() => setAssignOpen(true)}><Plus />{t('roleAssignments.assign')}</Button> : null}
    </CardHeader>
    <CardContent className='space-y-4'>
      <DataTable
        columns={columns}
        data={assignments.data?.items ?? []}
        getRowId={(assignment) => `${assignment.user_id}:${assignment.role_id}`}
        isLoading={assignments.isLoading}
        isRefreshing={assignments.isFetching && !assignments.isLoading}
        error={assignments.error}
        onRetry={() => void assignments.refetch()}
        search={{ value: search, onChange: (value) => { setSearch(value); setPage(1) }, fields: ['role_id', 'source', 'granted_by'], placeholder: t('roleAssignments.searchPlaceholder') }}
        toolbarFilters={<Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-52`} value={status} onChange={(event) => { setStatus(event.target.value.trim().toLowerCase()); setPage(1) }} placeholder={t('roleAssignments.statusFilterPlaceholder')} aria-label={t('roleAssignments.statusFilterPlaceholder')} />}
        hasActiveToolbarFilters={Boolean(status)}
        manualPagination={{ page, pageSize, total: assignments.data?.total ?? 0, onChange: (nextPage, nextPageSize) => { setPage(nextPageSize === pageSize ? nextPage : 1); setPageSize(nextPageSize) } }}
        pageSizeOptions={[10, 20, 50]}
      />
      <Dialog open={assignOpen} onOpenChange={(open) => !assign.isPending && setAssignOpen(open)}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('roleAssignments.assign')}</DialogTitle><DialogDescription>{t('roleAssignments.assignDescription')}</DialogDescription></DialogHeader>
          <div className='space-y-4'>
            <Field><FieldLabel>{t('roleAssignments.role')}</FieldLabel><Select value={roleID} onValueChange={setRoleID}><SelectTrigger><SelectValue placeholder={t('roleAssignments.rolePlaceholder')} /></SelectTrigger><SelectContent>{(roles.data ?? []).map((role) => <SelectItem key={role.id} value={role.id}>{role.name || role.code}</SelectItem>)}</SelectContent></Select></Field>
            <Field><FieldLabel htmlFor={`role-assignment-reason-${userID}`}>{t('roleAssignments.reason')}</FieldLabel><Input id={`role-assignment-reason-${userID}`} value={reason} onChange={(event) => setReason(event.target.value)} /></Field>
          </div>
          <DialogFooter><Button variant='outline' disabled={assign.isPending} onClick={() => setAssignOpen(false)}>{t('common.cancel')}</Button><Button disabled={assign.isPending || !roleID || !reason.trim()} onClick={() => assign.mutate()}>{t('roleAssignments.assign')}</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </CardContent>
  </Card>
}
