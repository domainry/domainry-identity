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
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
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
  useCreateOrganizationUnit,
  useOrganizationUnits,
  useUpdateOrganizationUnit,
} from '@/data/hooks'
import type { OrganizationUnit, EntityStatus } from '@/data/types'
import { runtimeApiError } from '@/lib/runtime-api'
import { runtimeErrorConstraintMessage } from '@/lib/runtime-error-details'
import { organizationUnitFormControl } from '@/features/org/identity-form-error'

/* ------------------------------------------------------------------ */
/* Domain model                                                        */
/* ------------------------------------------------------------------ */

type OrganizationUnitStatus = EntityStatus

/* ------------------------------------------------------------------ */
/* Tree helpers                                                        */
/* ------------------------------------------------------------------ */

function buildTree(
  t: Translate,
  organizationUnits: OrganizationUnit[],
  excludeIds?: Set<string>
): TreeNode[] {
  const byParent = new Map<string | null, OrganizationUnit[]>()
  for (const unit of organizationUnits) {
    if (excludeIds?.has(unit.id)) continue
    const list = byParent.get(unit.parentId) ?? []
    list.push(unit)
    byParent.set(unit.parentId, list)
  }
  const toNodes = (parentId: string | null): TreeNode[] =>
    (byParent.get(parentId) ?? []).map((unit) => ({
      id: unit.id,
      label: displayText(t, unit.name),
      children: toNodes(unit.id),
    }))
  return toNodes(null)
}

/** Ids of `rootId` plus all of its descendants. */
function collectSubtreeIds(organizationUnits: OrganizationUnit[], rootId: string): Set<string> {
  const ids = new Set<string>([rootId])
  let changed = true
  while (changed) {
    changed = false
    for (const unit of organizationUnits) {
      if (unit.parentId && ids.has(unit.parentId) && !ids.has(unit.id)) {
        ids.add(unit.id)
        changed = true
      }
    }
  }
  return ids
}

function organizationUnitPath(t: Translate, organizationUnits: OrganizationUnit[], id: string | null): string {
  const byId = new Map(organizationUnits.map((d) => [d.id, d]))
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
  /** OrganizationUnit being edited; null means creating. */
  editing: OrganizationUnit | null
  /** Preset parent when creating a child from a row action. */
  presetParentId: string | null
}

function OrganizationUnitFormDialog({
  state,
  organizationUnits,
  isPending,
  onClose,
  onSubmit,
}: {
  state: DialogState
  organizationUnits: OrganizationUnit[]
  isPending: boolean
  onClose: () => void
  onSubmit: (values: {
    code: string
    name: string
    nodeType: OrganizationUnit['nodeType']
    parentId: string | null
    status: OrganizationUnitStatus
  }) => Promise<void>
}) {
  const { t } = useI18n()
  const { editing, presetParentId } = state
  const [discardOpen, setDiscardOpen] = useState(false)
  const schema = useMemo(
    () =>
      z
        .object({
          code: z.string().trim().min(1, t('organizationUnit.validation.codeRequired')),
          name: z.string().trim().min(1, t('organizationUnit.validation.nameRequired')),
          nodeType: z.enum(['company', 'region', 'store', 'department', 'team', 'warehouse']),
          parentId: z.string(),
          enabled: z.boolean(),
        })
        .superRefine((values, context) => {
          const parent = values.parentId === ROOT_OPTION_ID ? null : values.parentId
          if (
            organizationUnits.some(
              (organizationUnit) =>
                organizationUnit.id !== editing?.id &&
                organizationUnit.parentId === parent &&
                displayText(t, organizationUnit.name).trim().toLowerCase() ===
                  values.name.trim().toLowerCase()
            )
          ) {
            context.addIssue({
              code: 'custom',
              path: ['name'],
              message: t('organizationUnit.validation.nameUnique'),
            })
          }
        }),
    [organizationUnits, editing?.id, t]
  )
  type OrganizationUnitFormValues = z.input<typeof schema>
  const {
    control,
    register,
    handleSubmit,
    setError,
    formState: { errors, isDirty },
  } = useForm<OrganizationUnitFormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      code: editing?.code ?? '',
      name: editing ? displayText(t, editing.name) : '',
      nodeType: editing?.nodeType ?? 'department',
      parentId: editing?.parentId ?? presetParentId ?? ROOT_OPTION_ID,
      enabled: editing ? editing.status === 'active' : true,
    },
    mode: 'onBlur',
  })

  // Prevent cycles: an edited organizationUnit cannot be moved under itself.
  const excluded = useMemo(
    () => (editing ? collectSubtreeIds(organizationUnits, editing.id) : undefined),
    [organizationUnits, editing]
  )
  const parentTree = useMemo<TreeNode[]>(
    () => [
      { id: ROOT_OPTION_ID, label: t('organizationUnit.rootOption') },
      ...buildTree(t, organizationUnits, excluded),
    ],
    [organizationUnits, excluded, t]
  )

  const requestClose = () => {
    if (isDirty) setDiscardOpen(true)
    else onClose()
  }

  const submit = async (values: OrganizationUnitFormValues) => {
    try {
      await onSubmit({
        code: values.code.trim(),
        name: values.name.trim(),
        nodeType: values.nodeType,
        parentId: values.parentId === ROOT_OPTION_ID ? null : values.parentId,
        status: values.enabled ? 'active' : 'disabled',
      })
      onClose()
    } catch (error) {
      const structured = runtimeApiError(error)
      setError(organizationUnitFormControl(structured) ?? 'root', { message: runtimeErrorConstraintMessage(t, structured, error instanceof Error ? error.message : t('dataTable.errorDescription')) })
    }
  }

  return (
    <>
      <Dialog open={state.open} onOpenChange={(open) => !open && requestClose()}>
        <DialogContent className='sm:max-w-md'>
          <DialogHeader>
            <DialogTitle>{editing ? t('organizationUnit.dialog.editTitle') : t('organizationUnit.new')}</DialogTitle>
            <DialogDescription>
              {editing ? t('organizationUnit.dialog.editDesc') : t('organizationUnit.dialog.createDesc')}
            </DialogDescription>
          </DialogHeader>
          <form className='contents' onSubmit={handleSubmit(submit)} noValidate>
            <FieldGroup>
              <Field data-invalid={Boolean(errors.code)}>
                <FieldLabel htmlFor='unit-code'>{t('organizationUnit.form.code')}</FieldLabel>
                <Input id='unit-code' placeholder='EAST_STORE' aria-invalid={Boolean(errors.code)} {...register('code')} />
                <FieldError errors={[errors.code]} />
              </Field>
              <Field data-invalid={Boolean(errors.name)}>
                <FieldLabel htmlFor='unit-name'>{t('organizationUnit.form.name')}</FieldLabel>
                <Input
                  id='unit-name'
                  placeholder={t('organizationUnit.form.namePlaceholder')}
                  autoFocus
                  aria-invalid={Boolean(errors.name)}
                  {...register('name')}
                />
                <FieldError errors={[errors.name]} />
              </Field>
              <Field data-invalid={Boolean(errors.nodeType)}>
                <FieldLabel>{t('organizationUnit.form.nodeType')}</FieldLabel>
                <Controller control={control} name='nodeType' render={({ field }) => (
                  <Select value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {(['company', 'region', 'store', 'department', 'team', 'warehouse'] as const).map((type) => (
                        <SelectItem key={type} value={type}>{t(`organizationUnit.nodeType.${type}`)}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                )} />
                <FieldError errors={[errors.nodeType]} />
              </Field>
              <Field data-invalid={Boolean(errors.parentId)}>
                <FieldLabel>{t('organizationUnit.form.parent')}</FieldLabel>
                <Controller
                  control={control}
                  name='parentId'
                  render={({ field }) => (
                    <TreeSelect
                      data={parentTree}
                      value={field.value}
                      onValueChange={field.onChange}
                      leafOnly={false}
                      placeholder={t('organizationUnit.form.parentPlaceholder')}
                      searchPlaceholder={t('organizationUnit.form.parentSearch')}
                      emptyText={t('organizationUnit.form.parentEmpty')}
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
                <FieldLabel>{t('organizationUnit.form.enable')}</FieldLabel>
                <FieldError errors={[errors.enabled]} />
              </Field>
            </FieldGroup>
            <FieldError errors={[errors.root]} />
            <DialogFooter>
              <Button type='button' variant='outline' onClick={requestClose}>
                {t('organizationUnit.form.cancel')}
              </Button>
              <Button type='submit' disabled={isPending}>
                {editing ? t('organizationUnit.form.save') : t('organizationUnit.form.create')}
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

export function OrganizationUnitManagementPage() {
  const { t } = useI18n()
  const { has } = usePermissions()
  const { data: organizationUnits = [], isLoading, isError, refetch } = useOrganizationUnits()
  const createOrganizationUnit = useCreateOrganizationUnit()
  const updateOrganizationUnit = useUpdateOrganizationUnit()
  const [selectedId, setSelectedId] = useState<string | undefined>(undefined)
  const [keyword, setKeyword] = useState('')
  const [statusTarget, setStatusTarget] = useState<OrganizationUnit | null>(null)
  const [dialog, setDialog] = useState<DialogState>({
    open: false,
    editing: null,
    presetParentId: null,
  })

  const treeNodes = useMemo(
    () => organizationUnits.map((organizationUnit) => ({
      id: organizationUnit.id,
      label: displayText(t, organizationUnit.name),
      parentId: organizationUnit.parentId,
      sort: organizationUnit.sort,
    })),
    [organizationUnits, t]
  )

  const visibleOrganizationUnits = useMemo(() => {
    const scope = selectedId ? collectSubtreeIds(organizationUnits, selectedId) : null
    const query = keyword.trim().toLowerCase()
    return organizationUnits.filter((unit) => {
      if (scope && !scope.has(unit.id)) return false
      if (!query) return true
      return `${unit.code} ${displayText(t, unit.name)} ${unit.nodeType}`.toLowerCase().includes(query)
    })
  }, [organizationUnits, selectedId, keyword, t])

  const activeCount = organizationUnits.filter((unit) => unit.status === 'active').length
  const disabledCount = organizationUnits.filter((unit) => unit.status === 'disabled').length
  const today = () => new Date().toISOString().slice(0, 10)

  const openCreate = (presetParentId: string | null = null) =>
    setDialog({ open: true, editing: null, presetParentId })
  const openEdit = (unit: OrganizationUnit) =>
    setDialog({ open: true, editing: unit, presetParentId: null })
  const closeDialog = () => setDialog({ open: false, editing: null, presetParentId: null })

  const handleSubmit = async (values: {
    code: string
    name: string
    nodeType: OrganizationUnit['nodeType']
    parentId: string | null
    status: OrganizationUnitStatus
  }) => {
    if (dialog.editing) {
      await updateOrganizationUnit.mutateAsync({ id: dialog.editing.id, patch: values })
      toast.success(t('organizationUnit.toast.updated', { name: values.name }))
    } else {
      const siblingSort = organizationUnits
        .filter((organizationUnit) => organizationUnit.parentId === values.parentId)
        .reduce((maximum, organizationUnit) => Math.max(maximum, organizationUnit.sort), 0)
      await createOrganizationUnit.mutateAsync({ ...values, memberCount: 0, sort: siblingSort + 10, remark: '', updatedAt: today() })
      toast.success(t('organizationUnit.toast.created', { name: values.name }))
    }
  }

  const toggleStatus = (unit: OrganizationUnit) => {
    setStatusTarget(unit)
  }

  const confirmStatusToggle = () => {
    if (!statusTarget) return
    const unit = statusTarget
    const next: OrganizationUnitStatus = unit.status === 'active' ? 'disabled' : 'active'
    const name = displayText(t, unit.name)
    updateOrganizationUnit.mutate(
      { id: unit.id, patch: { status: next, updatedAt: today() } },
      {
        onSuccess: () => {
          setStatusTarget(null)
          toast.success(
            t(next === 'active' ? 'organizationUnit.toast.enabled' : 'organizationUnit.toast.disabled', { name })
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

  const moveOrganizationUnit = async ({ id, parentId, orderedIds }: SortableTreeMove) => {
    await Promise.all(
      orderedIds.map((organizationUnitID, index) =>
        updateOrganizationUnit.mutateAsync({
          id: organizationUnitID,
          patch: {
            sort: (index + 1) * 10,
            ...(organizationUnitID === id ? { parentId } : {}),
          },
        })
      )
    )
    toast.success(t('organizationUnit.tree.moveSuccess'))
  }

  return (
    <main className='w-full px-6 py-6'>
      {/* Topbar */}
      <div className='mb-4 flex flex-col gap-3 md:flex-row md:items-end md:justify-between'>
        <div>
          <div className='mb-1 text-xs tracking-wide text-muted-foreground'>
            {t('organizationUnit.crumb')}
          </div>
          <h1 className='font-display text-xl font-extrabold tracking-tight'>
            {t('organizationUnit.title')}
          </h1>
        </div>
        <div className='flex items-center gap-2'>
          <InputGroup className={`${DATA_TABLE_TOOLBAR_CONTROL_CLASS} w-56`}>
            <InputGroupAddon>
              <Search className='size-4' />
            </InputGroupAddon>
            <InputGroupInput
              placeholder={t('organizationUnit.searchPlaceholder')}
              value={keyword}
              onChange={(event) => setKeyword(event.target.value)}
            />
          </InputGroup>
          <Button variant='primary-glow' disabled={!has('identity.organization_units.create')} onClick={() => openCreate()}>
            <Plus data-icon='inline-start' />
            {t('organizationUnit.new')}
          </Button>
        </div>
      </div>

      {isLoading ? <div className='grid gap-3' aria-label={t('organizationUnit.loading')}>
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
          label={t('organizationUnit.kpi.total')}
          value={organizationUnits.length}
          delta={t('organizationUnit.kpi.totalDelta')}
          deltaTone='neutral'
        />
        <StatCard
          label={t('organizationUnit.kpi.active')}
          value={activeCount}
          delta={t('organizationUnit.kpi.activeDelta')}
          deltaTone='neutral'
        />
        <StatCard
          label={t('organizationUnit.kpi.disabled')}
          value={
            disabledCount > 0 ? (
              <span className='text-overdue'>{disabledCount}</span>
            ) : (
              disabledCount
            )
          }
          delta={
            disabledCount > 0
              ? t('organizationUnit.kpi.disabledDeltaSome')
              : t('organizationUnit.kpi.disabledDeltaNone')
          }
          deltaTone={disabledCount > 0 ? 'down' : 'neutral'}
        />
      </StatGrid>

      <div className='grid items-start gap-4 lg:grid-cols-[260px_1fr]'>
        {/* Org tree */}
        <SortableTreePanel
          title={t('organizationUnit.tree.title')}
          description={t('organizationUnit.tree.dragHint')}
          allLabel={t('organizationUnit.tree.all')}
          dragLabel={(label) => t('organizationUnit.tree.dragAria', { name: label })}
          collapseLabel={(label) => t('tree.collapse', { name: label })}
          expandLabel={(label) => t('tree.expand', { name: label })}
          searchPlaceholder={t('organizationUnit.tree.searchPlaceholder')}
          nodes={treeNodes}
          selectedId={selectedId}
          disabled={!has('identity.organization_units.update') || isLoading}
          onSelect={setSelectedId}
          onMove={moveOrganizationUnit}
          onMoveError={(error) => toast.error(error instanceof Error ? error.message : t('organizationUnit.tree.moveFailed'))}
        />

        {/* OrganizationUnit table */}
        <Card>
          <CardHeader>
            <CardTitle className='flex items-center justify-between text-base'>
              <span>
                {selectedId ? organizationUnitPath(t, organizationUnits, selectedId) : t('organizationUnit.tree.all')}
                <span className='ms-2 text-sm font-normal text-muted-foreground'>
                  {t('organizationUnit.count', { count: visibleOrganizationUnits.length })}
                </span>
              </span>
              {selectedId ? (
                <Button
                  variant='outline'
                  size='sm'
                  disabled={!has('identity.organization_units.create')}
                  onClick={() => openCreate(selectedId)}
                >
                  <Plus data-icon='inline-start' />
                  {t('organizationUnit.addChild')}
                </Button>
              ) : null}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {visibleOrganizationUnits.length === 0 ? (
              <EmptyState
                icon={Users}
                title={t(keyword.trim() || selectedId ? 'organizationUnit.filteredEmpty.title' : 'organizationUnit.empty.title')}
                description={t(keyword.trim() || selectedId ? 'organizationUnit.filteredEmpty.desc' : 'organizationUnit.empty.desc')}
                action={<Button size='sm' variant='outline' disabled={!has('identity.organization_units.create')} onClick={() => openCreate(selectedId ?? null)}>{t('organizationUnit.new')}</Button>}
              />
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('organizationUnit.table.name')}</TableHead>
                    <TableHead>{t('organizationUnit.table.type')}</TableHead>
                    <TableHead>{t('organizationUnit.table.parent')}</TableHead>
                    <TableHead className='text-right'>{t('organizationUnit.table.members')}</TableHead>
                    <TableHead>{t('organizationUnit.table.status')}</TableHead>
                    <TableHead className='sticky right-0 z-20 w-[1%] whitespace-nowrap border-l bg-background px-3 text-center'>{t('organizationUnit.table.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {visibleOrganizationUnits.map((unit) => (
                    <TableRow key={unit.id} className='group'>
                      <TableCell>
                        <div className='font-semibold'>{displayText(t, unit.name)}</div>
                        <div className='text-xs text-muted-foreground'>{unit.code}</div>
                        {unit.remark ? (
                          <div className='text-xs text-muted-foreground'>
                            {displayText(t, unit.remark)}
                          </div>
                        ) : null}
                      </TableCell>
                      <TableCell>{t(`organizationUnit.nodeType.${unit.nodeType}`)}</TableCell>
                      <TableCell className='text-muted-foreground'>
                        {unit.parentId ? organizationUnitPath(t, organizationUnits, unit.parentId) : '—'}
                      </TableCell>
                      <TableCell className='num text-right'>{unit.memberCount}</TableCell>
                      <TableCell>
                        <StatusBadge value={unit.status}>
                          {unit.status === 'active'
                            ? t('organizationUnit.status.active')
                            : t('organizationUnit.status.disabled')}
                        </StatusBadge>
                      </TableCell>
                      <TableCell className='sticky right-0 z-10 w-[1%] whitespace-nowrap border-l bg-background px-3 group-hover:bg-(--surface-hover)'>
                        <DataTableRowActions
                          menuLabel={t('organizationUnit.actionsAria')}
                          primary={[{ label: t('organizationUnit.menu.edit'), icon: Pencil, disabled: !has('identity.organization_units.update'), onSelect: () => openEdit(unit) }]}
                          secondary={[
							{ label: t('organizationUnit.addChild'), icon: Plus, disabled: !has('identity.organization_units.create'), onSelect: () => openCreate(unit.id) },
							{ label: unit.status === 'active' ? t('organizationUnit.menu.disable') : t('organizationUnit.menu.enable'), icon: Power, disabled: !has('identity.organization_units.update'), onSelect: () => toggleStatus(unit) },
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
        <OrganizationUnitFormDialog
          key={dialog.editing?.id ?? dialog.presetParentId ?? 'create'}
          state={dialog}
          organizationUnits={organizationUnits}
          isPending={createOrganizationUnit.isPending || updateOrganizationUnit.isPending}
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
        pending={updateOrganizationUnit.isPending}
        destructive={statusTarget?.status === 'active'}
        onOpenChange={(open) => { if (!open) setStatusTarget(null) }}
        onConfirm={confirmStatusToggle}
      />
    </main>
  )
}
