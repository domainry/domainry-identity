import { useMemo, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { Controller, useForm } from 'react-hook-form'
import {
  Pencil,
  Plus,
  Power,
  Search,
  Users,
} from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
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
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
  Skeleton,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
  TreeSelect,
  type TreeNode,
} from '@domainry/ui'
import { StatCard, StatGrid } from '@/components/stat-card'
import { EmptyState } from '@/components/empty-state'
import { DATA_TABLE_TOOLBAR_CONTROL_CLASS, DataTableRowActions } from '@/components/data-table'
import { DestructiveConfirmationDialog } from '@/components/destructive-confirmation-dialog'
import { StatusBadge } from '@/components/status-badge'
import { SortableTreePanel, type SortableTreeMove } from '@/components/sortable-tree-panel'
import { useI18n, type Translate } from '@/lib/i18n'
import { usePermissions } from '@/lib/permissions'
import { displayText } from '@/data/text'
import {
  useCreateDepartment,
  useDepartments,
  useUpdateDepartment,
} from '@/data/hooks'
import type { Department, EntityStatus } from '@/data/types'
import { runtimeApiError } from '@/lib/runtime-api'
import { runtimeErrorConstraintMessage } from '@/lib/runtime-error-details'
import { departmentFormControl } from '@/features/org/identity-form-error'

/* ------------------------------------------------------------------ */
/* Domain model                                                        */
/* ------------------------------------------------------------------ */

type DeptStatus = EntityStatus

/* ------------------------------------------------------------------ */
/* Tree helpers                                                        */
/* ------------------------------------------------------------------ */

function buildTree(
  t: Translate,
  departments: Department[],
  excludeIds?: Set<string>
): TreeNode[] {
  const byParent = new Map<string | null, Department[]>()
  for (const dept of departments) {
    if (excludeIds?.has(dept.id)) continue
    const list = byParent.get(dept.parentId) ?? []
    list.push(dept)
    byParent.set(dept.parentId, list)
  }
  const toNodes = (parentId: string | null): TreeNode[] =>
    (byParent.get(parentId) ?? []).map((dept) => ({
      id: dept.id,
      label: displayText(t, dept.name),
      children: toNodes(dept.id),
    }))
  return toNodes(null)
}

/** Ids of `rootId` plus all of its descendants. */
function collectSubtreeIds(departments: Department[], rootId: string): Set<string> {
  const ids = new Set<string>([rootId])
  let changed = true
  while (changed) {
    changed = false
    for (const dept of departments) {
      if (dept.parentId && ids.has(dept.parentId) && !ids.has(dept.id)) {
        ids.add(dept.id)
        changed = true
      }
    }
  }
  return ids
}

function departmentPath(t: Translate, departments: Department[], id: string | null): string {
  const byId = new Map(departments.map((d) => [d.id, d]))
  const parts: string[] = []
  let current = id ? byId.get(id) : undefined
  while (current) {
    parts.unshift(displayText(t, current.name))
    current = current.parentId ? byId.get(current.parentId) : undefined
  }
  return parts.join(' / ')
}

const ROOT_OPTION_ID = '__root__'

/* ------------------------------------------------------------------ */
/* Create / edit dialog                                                */
/* ------------------------------------------------------------------ */

interface DialogState {
  open: boolean
  /** Department being edited; null means creating. */
  editing: Department | null
  /** Preset parent when creating a child from a row action. */
  presetParentId: string | null
}

function DepartmentFormDialog({
  state,
  departments,
  isPending,
  onClose,
  onSubmit,
}: {
  state: DialogState
  departments: Department[]
  isPending: boolean
  onClose: () => void
  onSubmit: (values: {
    name: string
    parentId: string | null
    status: DeptStatus
  }) => Promise<void>
}) {
  const { t } = useI18n()
  const { editing, presetParentId } = state
  const [discardOpen, setDiscardOpen] = useState(false)
  const schema = useMemo(
    () =>
      z
        .object({
          name: z.string().trim().min(1, t('dept.validation.nameRequired')),
          parentId: z.string(),
          enabled: z.boolean(),
        })
        .superRefine((values, context) => {
          const parent = values.parentId === ROOT_OPTION_ID ? null : values.parentId
          if (
            departments.some(
              (department) =>
                department.id !== editing?.id &&
                department.parentId === parent &&
                displayText(t, department.name).trim().toLowerCase() ===
                  values.name.trim().toLowerCase()
            )
          ) {
            context.addIssue({
              code: 'custom',
              path: ['name'],
              message: t('dept.validation.nameUnique'),
            })
          }
        }),
    [departments, editing?.id, t]
  )
  type DepartmentFormValues = z.input<typeof schema>
  const {
    control,
    register,
    handleSubmit,
    setError,
    formState: { errors, isDirty },
  } = useForm<DepartmentFormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: editing ? displayText(t, editing.name) : '',
      parentId: editing?.parentId ?? presetParentId ?? ROOT_OPTION_ID,
      enabled: editing ? editing.status === 'active' : true,
    },
    mode: 'onBlur',
  })

  // Prevent cycles: an edited department cannot be moved under itself.
  const excluded = useMemo(
    () => (editing ? collectSubtreeIds(departments, editing.id) : undefined),
    [departments, editing]
  )
  const parentTree = useMemo<TreeNode[]>(
    () => [
      { id: ROOT_OPTION_ID, label: t('dept.rootOption') },
      ...buildTree(t, departments, excluded),
    ],
    [departments, excluded, t]
  )

  const requestClose = () => {
    if (isDirty) setDiscardOpen(true)
    else onClose()
  }

  const submit = async (values: DepartmentFormValues) => {
    try {
      await onSubmit({
        name: values.name.trim(),
        parentId: values.parentId === ROOT_OPTION_ID ? null : values.parentId,
        status: values.enabled ? 'active' : 'disabled',
      })
      onClose()
    } catch (error) {
      const structured = runtimeApiError(error)
      setError(departmentFormControl(structured) ?? 'root', { message: runtimeErrorConstraintMessage(t, structured, error instanceof Error ? error.message : t('dataTable.errorDescription')) })
    }
  }

  return (
    <>
      <Dialog open={state.open} onOpenChange={(open) => !open && requestClose()}>
        <DialogContent className='sm:max-w-md'>
          <DialogHeader>
            <DialogTitle>{editing ? t('dept.dialog.editTitle') : t('dept.new')}</DialogTitle>
            <DialogDescription>
              {editing ? t('dept.dialog.editDesc') : t('dept.dialog.createDesc')}
            </DialogDescription>
          </DialogHeader>
          <form className='contents' onSubmit={handleSubmit(submit)} noValidate>
            <FieldGroup>
              <Field data-invalid={Boolean(errors.name)}>
                <FieldLabel htmlFor='dept-name'>{t('dept.form.name')}</FieldLabel>
                <Input
                  id='dept-name'
                  placeholder={t('dept.form.namePlaceholder')}
                  autoFocus
                  aria-invalid={Boolean(errors.name)}
                  {...register('name')}
                />
                <FieldError errors={[errors.name]} />
              </Field>
              <Field data-invalid={Boolean(errors.parentId)}>
                <FieldLabel>{t('dept.form.parent')}</FieldLabel>
                <Controller
                  control={control}
                  name='parentId'
                  render={({ field }) => (
                    <TreeSelect
                      data={parentTree}
                      value={field.value}
                      onValueChange={field.onChange}
                      leafOnly={false}
                      placeholder={t('dept.form.parentPlaceholder')}
                      searchPlaceholder={t('dept.form.parentSearch')}
                      emptyText={t('dept.form.parentEmpty')}
                      className='w-full'
                    />
                  )}
                />
                <FieldError errors={[errors.parentId]} />
              </Field>
              <Field orientation='horizontal' data-invalid={Boolean(errors.enabled)}>
                <Controller
                  control={control}
                  name='enabled'
                  render={({ field }) => (
                    <Switch checked={field.value} onCheckedChange={field.onChange} />
                  )}
                />
                <FieldLabel>{t('dept.form.enable')}</FieldLabel>
                <FieldError errors={[errors.enabled]} />
              </Field>
            </FieldGroup>
            <FieldError errors={[errors.root]} />
            <DialogFooter>
              <Button type='button' variant='outline' onClick={requestClose}>
                {t('dept.form.cancel')}
              </Button>
              <Button type='submit' disabled={isPending}>
                {editing ? t('dept.form.save') : t('dept.form.create')}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
      <AlertDialog open={discardOpen} onOpenChange={setDiscardOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t('forms.discard.title')}</AlertDialogTitle>
            <AlertDialogDescription>{t('forms.discard.desc')}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t('forms.discard.keepEditing')}</AlertDialogCancel>
            <AlertDialogAction onClick={onClose}>{t('forms.discard.action')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

/* ------------------------------------------------------------------ */
/* Page                                                                */
/* ------------------------------------------------------------------ */

export function DepartmentManagementPage() {
  const { t } = useI18n()
  const { can } = usePermissions()
  const { data: departments = [], isLoading, isError, refetch } = useDepartments()
  const createDepartment = useCreateDepartment()
  const updateDepartment = useUpdateDepartment()
  const [selectedId, setSelectedId] = useState<string | undefined>(undefined)
  const [keyword, setKeyword] = useState('')
  const [statusTarget, setStatusTarget] = useState<Department | null>(null)
  const [dialog, setDialog] = useState<DialogState>({
    open: false,
    editing: null,
    presetParentId: null,
  })

  const treeNodes = useMemo(
    () => departments.map((department) => ({
      id: department.id,
      label: displayText(t, department.name),
      parentId: department.parentId,
      sort: department.sort,
    })),
    [departments, t]
  )

  const visibleDepartments = useMemo(() => {
    const scope = selectedId ? collectSubtreeIds(departments, selectedId) : null
    const query = keyword.trim().toLowerCase()
    return departments.filter((dept) => {
      if (scope && !scope.has(dept.id)) return false
      if (!query) return true
      return displayText(t, dept.name).toLowerCase().includes(query)
    })
  }, [departments, selectedId, keyword, t])

  const activeCount = departments.filter((dept) => dept.status === 'active').length
  const disabledCount = departments.filter((dept) => dept.status === 'disabled').length
  const today = () => new Date().toISOString().slice(0, 10)

  const openCreate = (presetParentId: string | null = null) =>
    setDialog({ open: true, editing: null, presetParentId })
  const openEdit = (dept: Department) =>
    setDialog({ open: true, editing: dept, presetParentId: null })
  const closeDialog = () => setDialog({ open: false, editing: null, presetParentId: null })

  const handleSubmit = async (values: {
    name: string
    parentId: string | null
    status: DeptStatus
  }) => {
    if (dialog.editing) {
      await updateDepartment.mutateAsync({ id: dialog.editing.id, patch: values })
      toast.success(t('dept.toast.updated', { name: values.name }))
    } else {
      const siblingSort = departments
        .filter((department) => department.parentId === values.parentId)
        .reduce((maximum, department) => Math.max(maximum, department.sort), 0)
      await createDepartment.mutateAsync({ ...values, leader: '', memberCount: 0, sort: siblingSort + 10, remark: '', updatedAt: today() })
      toast.success(t('dept.toast.created', { name: values.name }))
    }
  }

  const toggleStatus = (dept: Department) => {
    setStatusTarget(dept)
  }

  const confirmStatusToggle = () => {
    if (!statusTarget) return
    const dept = statusTarget
    const next: DeptStatus = dept.status === 'active' ? 'disabled' : 'active'
    const name = displayText(t, dept.name)
    updateDepartment.mutate(
      { id: dept.id, patch: { status: next, updatedAt: today() } },
      {
        onSuccess: () => {
          setStatusTarget(null)
          toast.success(
            t(next === 'active' ? 'dept.toast.enabled' : 'dept.toast.disabled', { name })
          )
        },
        onError: (error) => toast.error(runtimeErrorConstraintMessage(
          t,
          runtimeApiError(error),
          error instanceof Error ? error.message : t('dataTable.errorDescription')
        )),
      }
    )
  }

  const moveDepartment = async ({ id, parentId, orderedIds }: SortableTreeMove) => {
    await Promise.all(
      orderedIds.map((departmentID, index) =>
        updateDepartment.mutateAsync({
          id: departmentID,
          patch: {
            sort: (index + 1) * 10,
            ...(departmentID === id ? { parentId } : {}),
          },
        })
      )
    )
    toast.success(t('dept.tree.moveSuccess'))
  }

  return (
    <main className='w-full px-6 py-6'>
      {/* Topbar */}
      <div className='mb-4 flex flex-col gap-3 md:flex-row md:items-end md:justify-between'>
        <div>
          <div className='mb-1 text-xs tracking-wide text-muted-foreground'>
            {t('dept.crumb')}
          </div>
          <h1 className='font-display text-xl font-extrabold tracking-tight'>
            {t('dept.title')}
          </h1>
        </div>
        <div className='flex items-center gap-2'>
          <InputGroup className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-56`}>
            <InputGroupAddon>
              <Search className='size-4' />
            </InputGroupAddon>
            <InputGroupInput
              placeholder={t('dept.searchPlaceholder')}
              value={keyword}
              onChange={(event) => setKeyword(event.target.value)}
            />
          </InputGroup>
          <Button variant='primary-glow' disabled={!can('departments', 'create')} onClick={() => openCreate()}>
            <Plus data-icon='inline-start' />
            {t('dept.new')}
          </Button>
        </div>
      </div>

      {isLoading ? <div className='grid gap-3' aria-label={t('dept.loading')}>
        <StatGrid className='grid-cols-2 sm:grid-cols-3'>
          <Skeleton className='h-24 rounded-lg' />
          <Skeleton className='h-24 rounded-lg' />
          <Skeleton className='h-24 rounded-lg' />
        </StatGrid>
        <Skeleton className='h-72 rounded-lg' />
      </div> : null}

      {isError ? <Alert variant='destructive'>
        <AlertTitle>{t('dataTable.errorTitle')}</AlertTitle>
        <AlertDescription className='flex flex-wrap items-center justify-between gap-3'>
          <span>{t('dataTable.errorDescription')}</span>
          <Button size='sm' variant='outline' onClick={() => void refetch()}>{t('common.retry')}</Button>
        </AlertDescription>
      </Alert> : null}

      {!isLoading && !isError ? <>
      {/* KPIs */}
      <StatGrid className='mb-4 grid-cols-2 sm:grid-cols-3'>
        <StatCard
          label={t('dept.kpi.total')}
          value={departments.length}
          delta={t('dept.kpi.totalDelta')}
          deltaTone='neutral'
        />
        <StatCard
          label={t('dept.kpi.active')}
          value={activeCount}
          delta={t('dept.kpi.activeDelta')}
          deltaTone='neutral'
        />
        <StatCard
          label={t('dept.kpi.disabled')}
          value={
            disabledCount > 0 ? (
              <span className='text-overdue'>{disabledCount}</span>
            ) : (
              disabledCount
            )
          }
          delta={
            disabledCount > 0
              ? t('dept.kpi.disabledDeltaSome')
              : t('dept.kpi.disabledDeltaNone')
          }
          deltaTone={disabledCount > 0 ? 'down' : 'neutral'}
        />
      </StatGrid>

      <div className='grid items-start gap-4 lg:grid-cols-[260px_1fr]'>
        {/* Org tree */}
        <SortableTreePanel
          title={t('dept.tree.title')}
          description={t('dept.tree.dragHint')}
          allLabel={t('dept.tree.all')}
          dragLabel={(label) => t('dept.tree.dragAria', { name: label })}
          collapseLabel={(label) => t('tree.collapse', { name: label })}
          expandLabel={(label) => t('tree.expand', { name: label })}
          searchPlaceholder={t('dept.tree.searchPlaceholder')}
          nodes={treeNodes}
          selectedId={selectedId}
          disabled={!can('departments', 'edit') || isLoading}
          onSelect={setSelectedId}
          onMove={moveDepartment}
          onMoveError={(error) => toast.error(error instanceof Error ? error.message : t('dept.tree.moveFailed'))}
        />

        {/* Department table */}
        <Card>
          <CardHeader>
            <CardTitle className='flex items-center justify-between text-base'>
              <span>
                {selectedId ? departmentPath(t, departments, selectedId) : t('dept.tree.all')}
                <span className='ms-2 text-sm font-normal text-muted-foreground'>
                  {t('dept.count', { count: visibleDepartments.length })}
                </span>
              </span>
              {selectedId ? (
                <Button
                  variant='outline'
                  size='sm'
                  disabled={!can('departments', 'create')}
                  onClick={() => openCreate(selectedId)}
                >
                  <Plus data-icon='inline-start' />
                  {t('dept.addChild')}
                </Button>
              ) : null}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {visibleDepartments.length === 0 ? (
              <EmptyState
                icon={Users}
                title={t(keyword.trim() || selectedId ? 'dept.filteredEmpty.title' : 'dept.empty.title')}
                description={t(keyword.trim() || selectedId ? 'dept.filteredEmpty.desc' : 'dept.empty.desc')}
                action={<Button size='sm' variant='outline' disabled={!can('departments', 'create')} onClick={() => openCreate(selectedId ?? null)}>{t('dept.new')}</Button>}
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('dept.table.name')}</TableHead>
                    <TableHead>{t('dept.table.parent')}</TableHead>
                    <TableHead className='text-right'>{t('dept.table.members')}</TableHead>
                    <TableHead>{t('dept.table.status')}</TableHead>
                    <TableHead className='sticky right-0 z-20 w-[1%] whitespace-nowrap border-l bg-background px-3 text-center'>{t('dept.table.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleDepartments.map((dept) => (
                    <TableRow key={dept.id} className='group'>
                      <TableCell>
                        <div className='font-semibold'>{displayText(t, dept.name)}</div>
                        {dept.remark ? (
                          <div className='text-xs text-muted-foreground'>
                            {displayText(t, dept.remark)}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell className='text-muted-foreground'>
                        {dept.parentId ? departmentPath(t, departments, dept.parentId) : '—'}
                      </TableCell>
                      <TableCell className='num text-right'>{dept.memberCount}</TableCell>
                      <TableCell>
                        <StatusBadge value={dept.status}>
                          {dept.status === 'active'
                            ? t('dept.status.active')
                            : t('dept.status.disabled')}
                        </StatusBadge>
                      </TableCell>
                      <TableCell className='sticky right-0 z-10 w-[1%] whitespace-nowrap border-l bg-background px-3 group-hover:bg-(--surface-hover)'>
                        <DataTableRowActions
                          menuLabel={t('dept.actionsAria')}
                          primary={[{ label: t('dept.menu.edit'), icon: Pencil, disabled: !can('departments', 'edit'), onSelect: () => openEdit(dept) }]}
                          secondary={[
                            { label: t('dept.addChild'), icon: Plus, disabled: !can('departments', 'create'), onSelect: () => openCreate(dept.id) },
                            { label: dept.status === 'active' ? t('dept.menu.disable') : t('dept.menu.enable'), icon: Power, disabled: !can('departments', 'edit'), onSelect: () => toggleStatus(dept) },
                          ]}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>
      </> : null}

      {/* Create / edit dialog — keyed so fields reset per open target */}
      {dialog.open ? (
        <DepartmentFormDialog
          key={dialog.editing?.id ?? dialog.presetParentId ?? 'create'}
          state={dialog}
          departments={departments}
          isPending={createDepartment.isPending || updateDepartment.isPending}
          onClose={closeDialog}
          onSubmit={handleSubmit}
        />
      ) : null}
      <DestructiveConfirmationDialog
        open={statusTarget !== null}
        title={t(statusTarget?.status === 'active' ? 'common.disableTitle' : 'common.enableTitle', { name: statusTarget ? displayText(t, statusTarget.name) : '' })}
        description={t(statusTarget?.status === 'active' ? 'common.disableDescription' : 'common.enableDescription')}
        confirmLabel={t(statusTarget?.status === 'active' ? 'common.disable' : 'common.enable')}
        cancelLabel={t('common.cancel')}
        pending={updateDepartment.isPending}
        destructive={statusTarget?.status === 'active'}
        onOpenChange={(open) => { if (!open) setStatusTarget(null) }}
        onConfirm={confirmStatusToggle}
      />
    </main>
  )
}
