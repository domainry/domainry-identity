import { Fragment, useEffect, useMemo, useState, type ComponentType, type ReactNode } from 'react'
import {
  flexRender,
  getCoreRowModel,
  getFilteredRowModel,
  getPaginationRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type ColumnFiltersState,
  type Row,
  type RowData,
  type RowSelectionState,
  type SortingState,
  type Updater,
  type VisibilityState,
} from '@tanstack/react-table'

declare module '@tanstack/react-table' {
  interface ColumnMeta<TData extends RowData, TValue> {
    /** Returns true when this row has at least one meaningful action. */
    hasActions?: (row: TData) => boolean
  }
}
import { Columns3, Loader2, MoreHorizontal, Search } from 'lucide-react'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Checkbox,
  DropdownMenu,
  DropdownMenuCheckboxItem,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@domainry/ui'
import { useI18n } from '@/lib/i18n'
import { EmptyState } from '@/components/empty-state'
import { cn } from '@/lib/utils'

export const DATA_TABLE_TOOLBAR_CONTROL_CLASS = 'h-[36px]! min-h-[36px] [&_input]:h-[36px]!'
export const DATA_TABLE_ACTION_HEAD_CLASS = 'sticky right-0 z-20 w-[1%] whitespace-nowrap border-l bg-background px-3 text-center'
export const DATA_TABLE_ACTION_CELL_CLASS = 'sticky right-0 z-10 w-[1%] whitespace-nowrap border-l bg-background px-3 group-hover:bg-(--surface-hover) group-data-[state=selected]:bg-muted'

export function DataTableToolbar({ filters, actions }: { filters?: ReactNode; actions?: ReactNode }) {
  return (
    <div className='flex flex-wrap items-center justify-between gap-2' data-testid='data-table-toolbar'>
      <div className='flex flex-1 flex-wrap items-center gap-2'>{filters}</div>
      {actions ? <div className='flex items-center gap-2'>{actions}</div> : null}
    </div>
  )
}

export type DataTableRowAction = {
  label: ReactNode
  ariaLabel?: string
  onSelect: () => void
  icon?: ComponentType<{ className?: string; 'data-icon'?: string }>
  disabled?: boolean
  destructive?: boolean
  separatorBefore?: boolean
}

export type DataTableSearch = {
  /** Column ids in client mode; backend field keys in server mode. */
  fields: string[]
  placeholder?: string
  label?: string
  /** Supplying onChange enables debounced server-side search. */
  value?: string
  onChange?: (value: string, fields: string[]) => void
  debounceMs?: number
}

export function DataTableRowActions({
  primary = [],
  secondary = [],
  menuLabel,
}: {
  primary?: DataTableRowAction[]
  secondary?: DataTableRowAction[]
  menuLabel: string
}) {
  return (
    <div className='flex w-full items-center justify-center gap-1 whitespace-nowrap'>
      {primary.map((action, index) => {
        const Icon = action.icon
        if (Icon) {
          return (
            <Tooltip key={index}>
              <TooltipTrigger asChild>
                <Button
                  size='icon-sm'
                  variant='outline'
                  aria-label={action.ariaLabel ?? String(action.label)}
                  disabled={action.disabled}
                  onClick={action.onSelect}
                  className={cn(
                    'size-8 shrink-0 bg-background/90 text-muted-foreground shadow-xs transition-colors hover:bg-primary! hover:text-primary-foreground!',
                    action.destructive && 'text-destructive hover:bg-destructive/10 hover:text-destructive'
                  )}
                >
                  <Icon className='size-4' />
                </Button>
              </TooltipTrigger>
              <TooltipContent side='left'>{action.label}</TooltipContent>
            </Tooltip>
          )
        }
        return (
          <Button
            key={index}
            size='sm'
            variant='outline'
            disabled={action.disabled}
            onClick={action.onSelect}
            className={cn(
              'h-8 bg-background/90 shadow-xs hover:bg-primary! hover:text-primary-foreground!',
              action.destructive && 'border-destructive/30 text-destructive hover:bg-destructive/10 hover:text-destructive'
            )}
          >
            {action.label}
          </Button>
        )
      })}
      {secondary.length ? (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant='outline'
              size='icon-sm'
              aria-label={menuLabel}
              className='size-8 bg-background/90 text-muted-foreground shadow-xs hover:bg-primary! hover:text-primary-foreground!'
            >
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align='end'>
            <DropdownMenuGroup>
              {secondary.map((action, index) => {
                const Icon = action.icon
                return (
                  <Fragment key={index}>
                    {action.separatorBefore ? <DropdownMenuSeparator /> : null}
                    <DropdownMenuItem
                      variant={action.destructive ? 'destructive' : undefined}
                      disabled={action.disabled}
                      onSelect={action.onSelect}
                    >
                      {Icon ? <Icon /> : null}
                      {action.label}
                    </DropdownMenuItem>
                  </Fragment>
                )
              })}
            </DropdownMenuGroup>
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
    </div>
  )
}

type DataTableProps<TData> = {
  columns: ColumnDef<TData, unknown>[]
  data: TData[]
  columnLabels?: Record<string, string>
  getRowId?: (row: TData) => string
  isLoading?: boolean
  /** Keeps the current rows visible while a server-backed query refreshes. */
  isRefreshing?: boolean
  error?: Error | null
  onRetry?: () => void
  emptyTitle?: ReactNode
  emptyDescription?: ReactNode
  filteredEmptyTitle?: ReactNode
  filteredEmptyDescription?: ReactNode
  emptyAction?: ReactNode
  /** Page-specific actions rendered next to the column visibility control. */
  toolbarActions?: ReactNode
  /** Page-specific filters rendered with the built-in search box on the left side of the table toolbar. */
  toolbarFilters?: ReactNode
  /** Declares that at least one controlled toolbar filter is active. */
  hasActiveToolbarFilters?: boolean
  pageSizeOptions?: number[]
  /** One search box that can match multiple fields locally or through the backend. */
  search?: DataTableSearch
  filterableColumns?: { id: string; label: string; placeholder?: string }[]
  enableRowSelection?: boolean
  renderBulkActions?: (rows: Row<TData>[], clearSelection: () => void) => ReactNode
  cellClassName?: Record<string, string | undefined>
  headClassName?: Record<string, string | undefined>
  manualPagination?: {
    page: number
    pageSize: number
    total: number
    onChange: (page: number, pageSize: number) => void
  }
  manualSorting?: {
    value: SortingState
    onChange: (sorting: SortingState) => void
  }
  /** Keeps the action column visible while horizontally scrolling. */
  stickyActionColumn?: boolean
  /** Column id treated as the action column. */
  actionColumnId?: string
  /** Hides the action column when no row exposes an action. */
  hideEmptyActionColumn?: boolean
}

export function DataTable<TData>({
  columns,
  data,
  columnLabels = {},
  getRowId,
  isLoading = false,
  isRefreshing = false,
  error,
  onRetry,
  emptyTitle,
  emptyDescription,
  filteredEmptyTitle,
  filteredEmptyDescription,
  emptyAction,
  toolbarActions,
  toolbarFilters,
  hasActiveToolbarFilters = false,
  pageSizeOptions = [10, 20, 50],
  search,
  filterableColumns = [],
  enableRowSelection = false,
  renderBulkActions,
  cellClassName = {},
  headClassName = {},
  manualPagination,
  manualSorting,
  stickyActionColumn = true,
  actionColumnId = 'actions',
  hideEmptyActionColumn = true,
}: DataTableProps<TData>) {
  const { t } = useI18n()
  const [sorting, setSorting] = useState<SortingState>([])
  const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})
  const [columnFilters, setColumnFilters] = useState<ColumnFiltersState>([])
  const [globalFilter, setGlobalFilter] = useState('')
  const [searchDraft, setSearchDraft] = useState(search?.value ?? '')
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({})
  const [pagination, setPagination] = useState({ pageIndex: 0, pageSize: pageSizeOptions[0] ?? 10 })

  useEffect(() => {
    if (search?.onChange) setSearchDraft(search.value ?? '')
  }, [search?.onChange, search?.value])

  useEffect(() => {
    if (!search?.onChange || searchDraft === (search.value ?? '')) return
    const timer = window.setTimeout(
      () => search.onChange?.(searchDraft, search.fields),
      search.debounceMs ?? 300
    )
    return () => window.clearTimeout(timer)
  }, [search, searchDraft])

  const resolvedColumns = useMemo<ColumnDef<TData, unknown>[]>(() => {
    const actionColumn = columns.find((column) => column.id === actionColumnId)
    const hasActions = actionColumn?.meta?.hasActions
    const shouldHideActionColumn = Boolean(
      hideEmptyActionColumn && hasActions && !data.some((row) => hasActions(row))
    )
    const visibleColumns = shouldHideActionColumn
      ? columns.filter((column) => column.id !== actionColumnId)
      : columns
    const withActionDefaults = visibleColumns.map((column) =>
      column.id === actionColumnId
        ? { ...column, enableHiding: false, enableSorting: false }
        : column
    )
    if (!enableRowSelection) return withActionDefaults
    const selectionColumn: ColumnDef<TData, unknown> = {
      id: '__select__',
      enableHiding: false,
      enableSorting: false,
      header: ({ table }) => (
        <Checkbox
          aria-label={t('dataTable.selectPage')}
          checked={
            table.getIsAllPageRowsSelected()
              ? true
              : table.getIsSomePageRowsSelected()
                ? 'indeterminate'
                : false
          }
          onCheckedChange={(checked) => table.toggleAllPageRowsSelected(Boolean(checked))}
        />
      ),
      cell: ({ row }) => (
        <Checkbox
          aria-label={t('dataTable.selectRow')}
          checked={row.getIsSelected()}
          onCheckedChange={(checked) => row.toggleSelected(Boolean(checked))}
        />
      ),
    }
    return [selectionColumn, ...withActionDefaults]
  }, [actionColumnId, columns, data, enableRowSelection, hideEmptyActionColumn, t])

  const sortingState = manualSorting?.value ?? sorting
  const paginationState = manualPagination
    ? { pageIndex: Math.max(manualPagination.page - 1, 0), pageSize: manualPagination.pageSize }
    : pagination
  const updateSorting = (updater: Updater<SortingState>) => {
    const next = typeof updater === 'function' ? updater(sortingState) : updater
    if (manualSorting) manualSorting.onChange(next)
    else setSorting(next)
  }
  const updatePagination = (updater: Updater<typeof paginationState>) => {
    const next = typeof updater === 'function' ? updater(paginationState) : updater
    if (manualPagination) manualPagination.onChange(next.pageIndex + 1, next.pageSize)
    else setPagination(next)
  }

  const table = useReactTable({
    data,
    columns: resolvedColumns,
    getRowId,
    enableRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getFilteredRowModel: getFilteredRowModel(),
    getSortedRowModel: manualSorting ? undefined : getSortedRowModel(),
    getPaginationRowModel: manualPagination ? undefined : getPaginationRowModel(),
    manualSorting: Boolean(manualSorting),
    manualPagination: Boolean(manualPagination),
    manualFiltering: Boolean(search?.onChange),
    globalFilterFn: (row, _columnID, filterValue) => {
      const needle = String(filterValue ?? '').trim().toLocaleLowerCase()
      if (!needle) return true
      return (search?.fields ?? []).some((field) =>
        String(row.getValue(field) ?? '').toLocaleLowerCase().includes(needle)
      )
    },
    pageCount: manualPagination ? Math.max(Math.ceil(manualPagination.total / manualPagination.pageSize), 1) : undefined,
    onSortingChange: updateSorting,
    onPaginationChange: updatePagination,
    onColumnVisibilityChange: setColumnVisibility,
    onColumnFiltersChange: setColumnFilters,
    onGlobalFilterChange: setGlobalFilter,
    onRowSelectionChange: setRowSelection,
    state: { sorting: sortingState, pagination: paginationState, columnVisibility, columnFilters, globalFilter, rowSelection },
  })

  if (isLoading) {
    return <Skeleton className='h-72 w-full rounded-lg' />
  }
  if (error) {
    return (
      <Alert variant='destructive'>
        <AlertTitle>{t('dataTable.errorTitle')}</AlertTitle>
        <AlertDescription className='flex flex-wrap items-center justify-between gap-2'>
          <span>{error.message || t('dataTable.errorDescription')}</span>
          {onRetry ? <Button size='sm' variant='outline' onClick={onRetry}>{t('common.retry')}</Button> : null}
        </AlertDescription>
      </Alert>
    )
  }
  if (!data.length && !search && !toolbarFilters) {
    return (
      <EmptyState
        title={emptyTitle ?? t('common.emptyTitle')}
        description={emptyDescription ?? t('common.emptyDesc')}
        action={emptyAction}
      />
    )
  }

  const selectedRows = table.getSelectedRowModel().rows
  const pageCount = table.getPageCount()
  const pageIndex = table.getState().pagination.pageIndex
  const hideableColumns = table.getAllColumns().filter((column) => column.getCanHide())
  const hasActiveFilters = Boolean(
    (search && (search.onChange ? searchDraft : globalFilter).trim())
    || hasActiveToolbarFilters
    || columnFilters.some((filter) => String(filter.value ?? '').trim())
  )
  const resolvedEmptyTitle = hasActiveFilters
    ? filteredEmptyTitle ?? t('dataTable.filteredEmptyTitle')
    : emptyTitle ?? t('common.emptyTitle')
  const resolvedEmptyDescription = hasActiveFilters
    ? filteredEmptyDescription ?? t('dataTable.filteredEmptyDescription')
    : emptyDescription ?? t('common.emptyDesc')

  return (
    <div className='flex flex-col gap-3'>
      <DataTableToolbar
        filters={<>
          {search ? (
            <InputGroup className={cn(DATA_TABLE_TOOLBAR_CONTROL_CLASS, 'w-full sm:max-w-sm')}>
              <InputGroupAddon>
                <Search className='size-4' />
              </InputGroupAddon>
              <InputGroupInput
                aria-label={search.label ?? search.placeholder ?? t('dataTable.searchPlaceholder')}
                placeholder={search.placeholder ?? t('dataTable.searchPlaceholder')}
                value={search.onChange ? searchDraft : globalFilter}
                onChange={(event) => {
                  const value = event.target.value
                  if (search.onChange) setSearchDraft(value)
                  else {
                    setGlobalFilter(value)
                    table.setPageIndex(0)
                  }
                }}
              />
            </InputGroup>
          ) : null}
          {filterableColumns.map((filter) => (
            <InputGroup key={filter.id} className={cn(DATA_TABLE_TOOLBAR_CONTROL_CLASS, 'w-full sm:w-52')}>
              <InputGroupAddon>
                <Search className='size-4' />
              </InputGroupAddon>
              <InputGroupInput
                aria-label={filter.label}
                placeholder={filter.placeholder ?? t('dataTable.filterPlaceholder', { column: filter.label })}
                value={String(table.getColumn(filter.id)?.getFilterValue() ?? '')}
                onChange={(event) => table.getColumn(filter.id)?.setFilterValue(event.target.value)}
              />
            </InputGroup>
          ))}
          {toolbarFilters ? <div className='flex flex-wrap items-center gap-2' data-testid='data-table-toolbar-filters'>{toolbarFilters}</div> : null}
        </>}
        actions={<>
          {toolbarActions ? <div data-testid='data-table-toolbar-actions'>{toolbarActions}</div> : null}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant='outline' className={cn(DATA_TABLE_TOOLBAR_CONTROL_CLASS, 'hover:bg-primary hover:text-primary-foreground')}>
                <Columns3 data-icon='inline-start' />
                {t('dataTable.columns')}
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align='end'>
              <DropdownMenuLabel>{t('dataTable.columns')}</DropdownMenuLabel>
              <DropdownMenuGroup>
                {hideableColumns.map((column) => (
                  <DropdownMenuCheckboxItem
                    key={column.id}
                    checked={column.getIsVisible()}
                    onCheckedChange={(checked) => column.toggleVisibility(Boolean(checked))}
                  >
                    {columnLabels[column.id] ?? column.id}
                  </DropdownMenuCheckboxItem>
                ))}
              </DropdownMenuGroup>
            </DropdownMenuContent>
          </DropdownMenu>
        </>}
      />

      {isRefreshing && data.length ? (
        <div className='flex items-center gap-2 text-xs text-muted-foreground' role='status' data-testid='data-table-refreshing'>
          <Loader2 className='size-3.5 animate-spin' />
          {t('dataTable.refreshing')}
        </div>
      ) : null}

      <div className='max-w-full overflow-x-auto rounded-md border overscroll-x-contain [&>[data-slot=table-container]]:overflow-visible' role='region' aria-label={t('dataTable.scrollRegion')} tabIndex={0}>
        <Table className='min-w-[680px] [&_[data-slot=table-cell]]:min-w-0 [&_[data-slot=table-cell]]:overflow-hidden'>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    className={cn(
                      headClassName[header.column.id],
                      stickyActionColumn && header.column.id === actionColumnId && DATA_TABLE_ACTION_HEAD_CLASS
                    )}
                  >
                    {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.length ? table.getRowModel().rows.map((row) => (
              <TableRow key={row.id} className='group' data-state={row.getIsSelected() ? 'selected' : undefined}>
                {row.getVisibleCells().map((cell) => (
                  <TableCell
                    key={cell.id}
                    className={cn(
                      'min-w-0 overflow-hidden',
                      cellClassName[cell.column.id],
                      stickyActionColumn && cell.column.id === actionColumnId && DATA_TABLE_ACTION_CELL_CLASS
                    )}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </TableCell>
                ))}
              </TableRow>
            )) : <TableRow><TableCell colSpan={table.getVisibleLeafColumns().length} className='h-56'><EmptyState className='border-0' title={resolvedEmptyTitle} description={resolvedEmptyDescription} action={hasActiveFilters ? undefined : emptyAction} /></TableCell></TableRow>}
          </TableBody>
        </Table>
      </div>

      <div data-testid='data-table-pagination' className='flex flex-wrap items-center justify-between gap-3'>
        <div className='flex flex-wrap items-center gap-3'>
          <span data-testid='data-table-total' className='text-xs text-muted-foreground'>{t('common.count', { count: manualPagination?.total ?? table.getFilteredRowModel().rows.length })}</span>
          <span className='text-xs text-muted-foreground'>{t('dataTable.rowsPerPage')}</span>
          <Select
            value={String(table.getState().pagination.pageSize)}
            onValueChange={(value) => table.setPageSize(Number(value))}
          >
            <SelectTrigger size='sm' className='w-20'><SelectValue /></SelectTrigger>
            <SelectContent><SelectGroup>{pageSizeOptions.map((size) => <SelectItem key={size} value={String(size)}>{size}</SelectItem>)}</SelectGroup></SelectContent>
          </Select>
        </div>
        <div className='flex items-center gap-2'>
          <span className='text-xs text-muted-foreground'>
            {t('dataTable.pageInfo', { page: pageIndex + 1, total: Math.max(pageCount, 1) })}
          </span>
          <Button size='sm' variant='outline' disabled={isRefreshing || !table.getCanPreviousPage()} onClick={() => table.previousPage()}>{t('dataTable.prev')}</Button>
          <Button size='sm' variant='outline' disabled={isRefreshing || !table.getCanNextPage()} onClick={() => table.nextPage()}>{t('dataTable.next')}</Button>
        </div>
      </div>

      {selectedRows.length && renderBulkActions ? (
        <div role='toolbar' className='sticky bottom-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-popover p-3 shadow-lg'>
          <span className='text-sm font-medium'>{t('dataTable.selected', { count: selectedRows.length })}</span>
          <div className='flex flex-wrap items-center gap-2'>
            {renderBulkActions(selectedRows, () => table.resetRowSelection())}
            <Button size='sm' variant='ghost' onClick={() => table.resetRowSelection()}>{t('common.cancel')}</Button>
          </div>
        </div>
      ) : null}
    </div>
  )
}
