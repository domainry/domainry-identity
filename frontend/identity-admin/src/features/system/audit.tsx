import { useDeferredValue, useMemo, useState, type ReactNode } from 'react'
import type { ColumnDef } from '@tanstack/react-table'
import { Download, Eye, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import {
  Badge,
  Button,
  Card,
  CardContent,
  Input,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Separator,
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@domainry/ui'
import { TableColumnHeader } from '@domainry/ui/components/kibo-ui/table'
import {
  DATA_TABLE_ACTION_CELL_CLASS,
  DATA_TABLE_ACTION_HEAD_CLASS,
  DATA_TABLE_TOOLBAR_CONTROL_CLASS,
  DataTable,
  DataTableRowActions,
} from '@/components/data-table'
import { JsonCodeBlock } from '@/components/json-code-block'
import { RelativeDateTime } from '@/components/relative-date-time'
import { PageShell } from '@/components/page-shell'
import { StatusBadge } from '@/components/status-badge'
import { useI18n, type MessageKey } from '@/lib/i18n'
import { auditApi } from '@/data/api'
import { displayText } from '@/data/text'
import { useAuditLogs } from '@/data/hooks'
import type { AuditAction, AuditLog } from '@/data/types'

const ACTION_LABEL_KEYS: Record<AuditAction, MessageKey> = {
  create: 'audit.action.create',
  update: 'audit.action.update',
  delete: 'audit.action.delete',
  login: 'audit.action.login',
  export: 'audit.action.export',
}

const CELL_CLASS: Record<string, string | undefined> = {
  time: 'num text-sm text-muted-foreground',
  operator: 'text-sm font-medium',
  module: 'text-sm',
  detail: 'max-w-72 truncate text-sm text-muted-foreground',
  ip: 'num text-sm text-muted-foreground',
}

export function AuditPage() {
  const { t } = useI18n()
  const [resourceFilter, setResourceFilter] = useState('')
  const [recordFilter, setRecordFilter] = useState('')
  const [actorFilter, setActorFilter] = useState('')
  const [eventFilter, setEventFilter] = useState('')
  const [requestFilter, setRequestFilter] = useState('')
  const [createdFrom, setCreatedFrom] = useState('')
  const [createdTo, setCreatedTo] = useState('')
  const deferredFilters = useDeferredValue({
    resource: resourceFilter,
    recordId: recordFilter,
    actor: actorFilter,
    event: eventFilter,
    requestId: requestFilter,
  })
  const auditQuery = {
    ...deferredFilters,
    createdFrom: createdFrom ? new Date(`${createdFrom}T00:00:00`).toISOString() : undefined,
    createdTo: createdTo ? new Date(`${createdTo}T23:59:59.999`).toISOString() : undefined,
  }
  const logsQuery = useAuditLogs(auditQuery)
  const logs = logsQuery.data ?? []
  const [selectedLog, setSelectedLog] = useState<AuditLog>()
  const [exporting, setExporting] = useState(false)
  const [actionFilter, setActionFilter] = useState<string>('__all__')
  const [resultFilter, setResultFilter] = useState<string>('__all__')
  const [search, setSearch] = useState('')
  const hasFilters = Boolean(
    search.trim()
    || actionFilter !== '__all__'
    || resultFilter !== '__all__'
    || resourceFilter.trim()
    || recordFilter.trim()
    || actorFilter.trim()
    || eventFilter.trim()
    || requestFilter.trim()
    || createdFrom
    || createdTo
  )

  const visible = useMemo(() => {
    const query = search.trim().toLowerCase()
    return logs.filter((log) => {
      if (actionFilter !== '__all__' && log.action !== actionFilter) return false
      if (resultFilter !== '__all__' && log.result !== resultFilter) return false
      if (!query) return true
      return [log.time, displayText(t, log.operator), displayText(t, log.module), displayText(t, log.detail), log.ip]
        .some((value) => value.toLowerCase().includes(query))
    })
  }, [logs, actionFilter, resultFilter, search, t])

  const columns = useMemo<ColumnDef<AuditLog, unknown>[]>(() => [
    {
      accessorKey: 'time',
      header: ({ column }) => <TableColumnHeader column={column} title={t('audit.table.time')} />,
      cell: ({ row }) => <RelativeDateTime value={row.original.time} />,
    },
    {
      id: 'operator',
      accessorFn: (row) => displayText(t, row.operator),
      header: ({ column }) => <TableColumnHeader column={column} title={t('audit.table.operator')} />,
    },
    {
      accessorKey: 'action',
      header: ({ column }) => <TableColumnHeader column={column} title={t('audit.table.action')} />,
      cell: ({ row }) => <Badge variant='secondary' className='px-2 text-[11px]'>{t(ACTION_LABEL_KEYS[row.original.action])}</Badge>,
    },
    {
      id: 'module',
      accessorFn: (row) => displayText(t, row.module),
      header: ({ column }) => <TableColumnHeader column={column} title={t('audit.table.module')} />,
    },
    { id: 'detail', accessorFn: (row) => displayText(t, row.detail), enableSorting: false, header: () => t('audit.table.detail') },
    { accessorKey: 'ip', enableSorting: false, header: () => t('audit.table.ip') },
    {
      id: 'actions',
      header: t('audit.table.evidence'),
      enableSorting: false,
      cell: ({ row }) => (
        <DataTableRowActions
          menuLabel={t('common.actions')}
          primary={[{ label: t('audit.detail.open'), icon: Eye, onSelect: () => setSelectedLog(row.original) }]}
        />
      ),
    },
    {
      accessorKey: 'result',
      header: ({ column }) => <TableColumnHeader column={column} title={t('audit.table.result')} />,
      cell: ({ row }) => (
        <StatusBadge value={row.original.result}>
          {row.original.result === 'success' ? t('audit.result.success') : t('audit.result.failed')}
        </StatusBadge>
      ),
    },
  ], [t])

  const columnLabels = useMemo(() => ({
    time: t('audit.table.time'),
    operator: t('audit.table.operator'),
    action: t('audit.table.action'),
    module: t('audit.table.module'),
    detail: t('audit.table.detail'),
    ip: t('audit.table.ip'),
    result: t('audit.table.result'),
    actions: t('audit.table.evidence'),
  }), [t])

  async function exportAudit() {
    setExporting(true)
    try {
      const exported = await auditApi.export(auditQuery)
      const url = URL.createObjectURL(new Blob([JSON.stringify(exported, null, 2)], { type: 'application/json' }))
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = `identity-governance-audit-${new Date().toISOString().slice(0, 10)}.json`
      anchor.click()
      URL.revokeObjectURL(url)
      toast.success(t('audit.toast.exported', { count: exported.count }))
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('dataTable.errorDescription'))
    } finally {
      setExporting(false)
    }
  }

  function clearFilters() {
    setSearch('')
    setActionFilter('__all__')
    setResultFilter('__all__')
    setResourceFilter('')
    setRecordFilter('')
    setActorFilter('')
    setEventFilter('')
    setRequestFilter('')
    setCreatedFrom('')
    setCreatedTo('')
  }

  return (
    <PageShell
      title={t('audit.title')}
      description={t('audit.desc')}
      actions={(
        <Button variant='outline' disabled={exporting} onClick={() => void exportAudit()}>
          {exporting ? <Loader2 className='animate-spin' /> : <Download />}
          {t('audit.export')}
        </Button>
      )}
    >
      <Card>
        <CardContent className='pt-4'>
          <DataTable
            columns={columns}
            data={visible}
            columnLabels={columnLabels}
            getRowId={(log) => log.id}
            search={{ fields: ['time', 'operator', 'module', 'detail', 'ip'], placeholder: t('audit.searchPlaceholder'), value: search, onChange: setSearch }}
            toolbarFilters={(
              <>
                <Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('audit.filter.resource')} placeholder={t('audit.filter.resource')} value={resourceFilter} onChange={(event) => setResourceFilter(event.target.value)} />
                <Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('audit.filter.record')} placeholder={t('audit.filter.record')} value={recordFilter} onChange={(event) => setRecordFilter(event.target.value)} />
                <Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('audit.filter.operator')} placeholder={t('audit.filter.operator')} value={actorFilter} onChange={(event) => setActorFilter(event.target.value)} />
                <Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('audit.filter.changeType')} placeholder={t('audit.filter.changeType')} value={eventFilter} onChange={(event) => setEventFilter(event.target.value)} />
                <Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('audit.filter.request')} placeholder={t('audit.filter.request')} value={requestFilter} onChange={(event) => setRequestFilter(event.target.value)} />
                <Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('audit.filter.createdFrom')} type='date' value={createdFrom} onChange={(event) => setCreatedFrom(event.target.value)} />
                <Input className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-44`} aria-label={t('audit.filter.createdTo')} type='date' value={createdTo} onChange={(event) => setCreatedTo(event.target.value)} />
                <Select value={actionFilter} onValueChange={setActionFilter}>
                  <SelectTrigger className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-36`}><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup>
                    <SelectItem value='__all__'>{t('audit.filter.allActions')}</SelectItem>
                    {(Object.keys(ACTION_LABEL_KEYS) as AuditAction[]).map((action) => <SelectItem key={action} value={action}>{t(ACTION_LABEL_KEYS[action])}</SelectItem>)}
                  </SelectGroup></SelectContent>
                </Select>
                <Select value={resultFilter} onValueChange={setResultFilter}>
                  <SelectTrigger className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-36`}><SelectValue /></SelectTrigger>
                  <SelectContent><SelectGroup>
                    <SelectItem value='__all__'>{t('audit.filter.allResults')}</SelectItem>
                    <SelectItem value='success'>{t('audit.result.success')}</SelectItem>
                    <SelectItem value='failed'>{t('audit.result.failed')}</SelectItem>
                  </SelectGroup></SelectContent>
                </Select>
              </>
            )}
            hasActiveToolbarFilters={hasFilters}
            isLoading={logsQuery.isLoading}
            error={logsQuery.error}
            onRetry={() => void logsQuery.refetch()}
            emptyTitle={hasFilters ? t('dataTable.filteredEmptyTitle') : t('audit.empty.title')}
            emptyDescription={hasFilters ? t('dataTable.filteredEmptyDescription') : t('audit.empty.description')}
            actionColumnId='actions'
            headClassName={{ actions: DATA_TABLE_ACTION_HEAD_CLASS }}
            cellClassName={{ ...CELL_CLASS, actions: DATA_TABLE_ACTION_CELL_CLASS }}
            emptyAction={hasFilters ? <Button size='sm' variant='outline' onClick={clearFilters}>{t('common.clearFilters')}</Button> : undefined}
          />
        </CardContent>
      </Card>
      <Sheet open={Boolean(selectedLog)} onOpenChange={(open) => !open && setSelectedLog(undefined)}>
        <SheetContent className='w-full overflow-y-auto sm:max-w-2xl'>
          <SheetHeader>
            <SheetTitle>{t('audit.detail.title')}</SheetTitle>
            <SheetDescription>{selectedLog?.event ?? ''}</SheetDescription>
          </SheetHeader>
          {selectedLog ? (
            <div className='flex flex-col gap-4 px-4 pb-6'>
              <div className='grid gap-3 text-sm sm:grid-cols-2'>
                <AuditFact label={t('audit.table.time')} value={<RelativeDateTime value={selectedLog.time} />} />
                <AuditFact label={t('audit.table.operator')} value={displayText(t, selectedLog.operator)} />
                <AuditFact label={t('audit.detail.role')} value={selectedLog.roleKey || '—'} code />
                <AuditFact label={t('audit.detail.event')} value={selectedLog.event} code />
                <AuditFact label={t('audit.detail.resource')} value={selectedLog.resource || '—'} code />
                <AuditFact label={t('audit.detail.record')} value={selectedLog.recordId || '—'} code />
                <AuditFact label={t('audit.detail.request')} value={selectedLog.requestId || '—'} code />
                <AuditFact label={t('audit.detail.correlation')} value={selectedLog.correlationId || '—'} code />
              </div>
              <Separator />
              <div><div className='mb-1 text-xs font-medium text-muted-foreground'>{t('audit.table.detail')}</div><p className='text-sm'>{displayText(t, selectedLog.detail)}</p></div>
              <JsonCodeBlock value={selectedLog.metadata} filename='metadata.json' />
              {selectedLog.before ? <JsonCodeBlock value={selectedLog.before} filename='before.json' /> : null}
              {selectedLog.after ? <JsonCodeBlock value={selectedLog.after} filename='after.json' /> : null}
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
    </PageShell>
  )
}

function AuditFact({ label, value, code = false }: { label: string; value: ReactNode; code?: boolean }) {
  return (
    <div className='min-w-0 rounded-md border bg-muted/20 px-3 py-2'>
      <div className='text-xs text-muted-foreground'>{label}</div>
      {code ? <code className='mt-1 block break-all text-xs'>{value}</code> : <div className='mt-1 break-words'>{value}</div>}
    </div>
  )
}
