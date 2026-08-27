import { useMemo, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { Controller, useForm } from 'react-hook-form'
import type { ColumnDef } from '@tanstack/react-table'
import { Folder, Pencil, Plus, SquareMenu, Trash2 } from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Badge,
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
  FieldError,
  FieldGroup,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
} from '@domainry/ui'
import { TableColumnHeader } from '@domainry/ui/components/kibo-ui/table'
import { DataTable, DataTableRowActions } from '@/components/data-table'
import { DestructiveConfirmationDialog } from '@/components/destructive-confirmation-dialog'
import { PageShell } from '@/components/page-shell'
import { SortableTreePanel } from '@/components/sortable-tree-panel'
import { useI18n } from '@/lib/i18n'
import { systemMenuLabel } from '@/lib/system-menu-label'
import { displayText } from '@/data/text'
import { useCreateMenu, useDeleteMenu, useMenus, useMoveMenu, useUpdateMenu } from '@/data/hooks'
import type { MenuNode, MenuType } from '@/data/types'
import { runtimeApiError } from '@/lib/runtime-api'
import { runtimeErrorConstraintMessage } from '@/lib/runtime-error-details'
import { menuFieldError } from './menu-field-error'

interface FormState {
  id: string | null
  name: string
  code: string
  path: string
  type: MenuType
  parentId: string
  sort: string
}

const EMPTY_FORM: FormState = {
  id: null,
  name: '',
  code: '',
  path: '',
  type: 'page',
  parentId: '',
  sort: '1',
}

function menuDescendants(menus: MenuNode[], id: string) {
  const result = new Set<string>()
  const collect = (parentId: string) => {
    for (const menu of menus.filter((candidate) => candidate.parentId === parentId)) {
      result.add(menu.id)
      collect(menu.id)
    }
  }
  collect(id)
  return result
}

export function MenuManagementPage() {
  const { t } = useI18n()
  const menusQuery = useMenus()
  const menus = menusQuery.data ?? []
  const createMenuMut = useCreateMenu()
  const updateMenuMut = useUpdateMenu()
  const deleteMenuMut = useDeleteMenu()
  const moveMenuMut = useMoveMenu()
  const [selectedMenuId, setSelectedMenuId] = useState<string>()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [discardOpen, setDiscardOpen] = useState(false)
  const [deleting, setDeleting] = useState<MenuNode | null>(null)
  const [visibilityPending, setVisibilityPending] = useState(false)
  const formSchema = useMemo(() => z.object({
    id: z.string().nullable(),
    name: z.string().trim().min(1, t('menus.validation.nameRequired')),
    code: z.string().trim().min(1, t('menus.validation.codeRequired')).regex(/^[a-z][a-z0-9_-]*(?::[a-z][a-z0-9_-]*)*$/, t('menus.validation.codeFormat')),
    path: z.string(),
    type: z.enum(['group', 'page']),
    parentId: z.string(),
    sort: z.string().regex(/^\d+$/, t('menus.validation.sort')).refine((value) => Number(value) >= 0, t('menus.validation.sort')),
  }).superRefine((value, context) => {
    if (menus.some((menu) => menu.id !== value.id && menu.code.toLowerCase() === value.code.trim().toLowerCase())) {
      context.addIssue({ code: 'custom', path: ['code'], message: t('menus.validation.codeUnique') })
    }
    if (value.type === 'page' && !value.parentId) {
      context.addIssue({ code: 'custom', path: ['parentId'], message: t('menus.validation.parentRequired') })
    }
    if (value.type === 'page' && value.path.trim() && !value.path.trim().startsWith('/')) {
      context.addIssue({ code: 'custom', path: ['path'], message: t('menus.validation.pathFormat') })
    }
  }), [menus, t])
  const {
    control,
    register,
    reset,
    setError,
    watch,
    handleSubmit,
    formState: { errors, isDirty },
  } = useForm<FormState>({ resolver: zodResolver(formSchema), defaultValues: EMPTY_FORM, mode: 'onBlur' })
  const formID = watch('id')
  const formType = watch('type')
  const menuLabel = (menu: MenuNode) => systemMenuLabel(t, menu.code, displayText(t, menu.name))

  const rows = useMemo(
    () => menus
      .filter((menu) => menu.parentId === (selectedMenuId ?? null))
      .sort((left, right) => left.sort - right.sort || left.code.localeCompare(right.code)),
    [menus, selectedMenuId]
  )
  const parentOptions = useMemo(() => {
    const blocked = formID ? menuDescendants(menus, formID) : new Set<string>()
    if (formID) blocked.add(formID)
    return menus.filter(
      (menu) =>
        !menu.parentId
        && menu.type === 'group'
        && !blocked.has(menu.id),
    )
  }, [formID, menus])

  function openCreate(parentId?: string) {
    const nextSort = menus
      .filter((menu) => menu.parentId === (parentId ?? null))
      .reduce((maximum, menu) => Math.max(maximum, menu.sort), 0) + 10
    reset({ ...EMPTY_FORM, type: parentId ? 'page' : 'group', parentId: parentId ?? '', sort: String(nextSort) })
    setDialogOpen(true)
  }

  function openEdit(node: MenuNode) {
    reset({
      id: node.id,
      name: displayText(t, node.name),
      code: node.code,
      path: node.path,
      type: node.type,
      parentId: node.parentId ?? '',
      sort: String(node.sort),
    })
    setDialogOpen(true)
  }

  function requestDialogOpen(open: boolean) {
    if (!open && isDirty) {
      setDiscardOpen(true)
      return
    }
    setDialogOpen(open)
  }

  function closeForm() {
    setDialogOpen(false)
    reset(EMPTY_FORM)
  }

  function submit(form: FormState) {
    const sort = Number.parseInt(form.sort, 10)
    const name = form.name.trim()
    if (form.id) {
      const editing = menus.find((m) => m.id === form.id)
      updateMenuMut.mutate(
        {
          id: form.id,
          patch: {
            name,
            code: form.code.trim(),
            path: form.path.trim(),
            sort,
            parentId:
              editing?.type === 'page' ? form.parentId || editing.parentId : null,
          },
        },
        {
          onSuccess: () => {
            toast.success(t('menus.toast.updated', { name }))
            closeForm()
          },
          onError: (error) => { const structured = runtimeApiError(error); const issue = menuFieldError(structured, error.message); setError(issue.control ?? 'root', { message: runtimeErrorConstraintMessage(t, structured, issue.message) }) },
        }
      )
    } else {
      createMenuMut.mutate(
        {
          parentId: form.type === 'page' ? form.parentId || null : null,
          name,
          code: form.code.trim(),
          path: form.path.trim(),
          type: form.type,
          sort,
          visible: true,
        },
        {
          onSuccess: () => {
            toast.success(t('menus.toast.created', { name }))
            closeForm()
          },
          onError: (error) => { const structured = runtimeApiError(error); const issue = menuFieldError(structured, error.message); setError(issue.control ?? 'root', { message: runtimeErrorConstraintMessage(t, structured, issue.message) }) },
        }
      )
    }
  }

  async function toggleVisible(node: MenuNode, value: boolean) {
    const name = displayText(t, node.name)
    const updates = [{ id: node.id, patch: { visible: value } }]
    if (!value) {
      const descendants = menuDescendants(menus, node.id)
      for (const child of menus.filter((menu) => descendants.has(menu.id) && menu.visible)) {
        updates.push({ id: child.id, patch: { visible: false } })
      }
    }
    setVisibilityPending(true)
    try {
      await Promise.all(updates.map((update) => updateMenuMut.mutateAsync(update)))
      toast.success(
        value
          ? t('menus.toast.shown', { name })
          : t('menus.toast.hidden', { name })
      )
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('dataTable.errorDescription'))
    } finally {
      setVisibilityPending(false)
    }
  }

  function requestDelete(target: MenuNode) {
    setDeleting(target)
  }

  async function confirmDelete() {
    if (!deleting) return
    const name = displayText(t, deleting.name)
    const target = deleting
    const descendants = menuDescendants(menus, target.id)
    try {
      await deleteMenuMut.mutateAsync(target.id)
      if (selectedMenuId === target.id || (selectedMenuId && descendants.has(selectedMenuId))) {
        setSelectedMenuId(undefined)
      }
      toast.success(t('menus.toast.deleted', { name }))
      setDeleting(null)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : t('dataTable.errorDescription'))
    }
  }

  const columns = useMemo<ColumnDef<MenuNode, unknown>[]>(
    () => [
      {
        id: 'name',
        accessorFn: (node) => menuLabel(node),
        header: ({ column }) => <TableColumnHeader column={column} title={t('menus.table.name')} />,
        cell: ({ row }) => {
          const node = row.original
          return (
            <div className='flex items-center gap-2'>
              {node.type === 'group' ? <Folder className='size-4 shrink-0 text-muted-foreground' /> : <SquareMenu className='size-4 shrink-0 text-muted-foreground' />}
              <span className={node.type === 'group' ? 'text-sm font-semibold' : 'text-sm font-medium'}>{menuLabel(node)}</span>
              {node.type === 'group' ? <Badge variant='secondary'>{t('menus.type.group')}</Badge> : null}
            </div>
          )
        },
      },
      {
        accessorKey: 'code',
        header: ({ column }) => <TableColumnHeader column={column} title={t('menus.table.code')} />,
        cell: ({ row }) => <code className='rounded bg-muted px-1.5 py-0.5 text-xs'>{row.original.code}</code>,
      },
      {
        accessorKey: 'path',
        header: ({ column }) => <TableColumnHeader column={column} title={t('menus.table.path')} />,
        cell: ({ row }) => <span className='text-sm text-muted-foreground'>{row.original.path || '—'}</span>,
      },
      {
        accessorKey: 'sort',
        header: ({ column }) => <TableColumnHeader column={column} title={t('menus.table.sort')} />,
      },
      {
        accessorKey: 'visible',
        header: ({ column }) => <TableColumnHeader column={column} title={t('menus.table.visible')} />,
        cell: ({ row }) => <Switch aria-label={t('menus.table.visible')} checked={row.original.visible} disabled={visibilityPending} onCheckedChange={(checked) => void toggleVisible(row.original, checked)} />,
      },
      {
        id: 'actions',
        enableSorting: false,
        enableHiding: false,
        header: () => <span className='block text-center'>{t('common.actions')}</span>,
        cell: ({ row }) => <DataTableRowActions
          menuLabel={t('common.actions')}
          primary={[{ label: t('common.edit'), icon: Pencil, onSelect: () => openEdit(row.original) }]}
          secondary={[{ label: t('common.delete'), icon: Trash2, destructive: true, onSelect: () => requestDelete(row.original) }]}
        />,
      },
    ],
    [t, menus, visibilityPending]
  )
  const columnLabels = useMemo(() => ({ name: t('menus.table.name'), code: t('menus.table.code'), path: t('menus.table.path'), sort: t('menus.table.sort'), visible: t('menus.table.visible'), actions: t('common.actions') }), [t])

  return (
    <PageShell
      title={t('menus.title')}
      description={t('menus.desc')}
      actions={<Button variant='primary-glow' size='sm' onClick={() => openCreate()}><Plus data-icon='inline-start' />{t('menus.new')}</Button>}
    >
      <div className='grid min-w-0 gap-4 xl:grid-cols-[minmax(280px,0.75fr)_minmax(0,1.7fr)]'>
        <SortableTreePanel title={t('menus.tree.title')} description={t('menus.tree.desc')} allLabel={t('menus.tree.all')} dragLabel={(label) => t('menus.tree.drag', { label })} collapseLabel={(label) => t('menus.tree.collapse', { label })} expandLabel={(label) => t('menus.tree.expand', { label })} searchPlaceholder={t('menus.tree.search')} nodes={menus.map((menu) => ({ id: menu.id, label: menuLabel(menu), parentId: menu.parentId, sort: menu.sort, icon: menu.type === 'group' ? <Folder /> : <SquareMenu />, disabled: !menu.visible }))} selectedId={selectedMenuId} disabled={moveMenuMut.isPending} treeViewportClassName='h-[520px]' onSelect={setSelectedMenuId} onMove={(move) => moveMenuMut.mutateAsync(move).then(() => { toast.success(t('menus.toast.moved')); return undefined })} onMoveError={(error) => toast.error(error instanceof Error ? error.message : t('dataTable.errorDescription'))} />
        <Card className='min-w-0'><CardContent className='min-w-0 pt-4'>
          <div className='mb-3 flex justify-end'>
            <Button variant='outline' size='sm' disabled={!selectedMenuId} onClick={() => selectedMenuId && openCreate(selectedMenuId)}>
              <Plus data-icon='inline-start' />
              {t('menus.newChild')}
            </Button>
          </div>
          <DataTable
            columns={columns}
            data={rows}
            columnLabels={columnLabels}
            getRowId={(menu) => menu.id}
            isLoading={menusQuery.isLoading}
            error={menusQuery.error}
            onRetry={() => void menusQuery.refetch()}
            emptyTitle={selectedMenuId ? t('menus.filteredEmptyTitle') : t('menus.emptyTitle')}
            emptyDescription={selectedMenuId ? t('menus.filteredEmptyDescription') : t('menus.emptyDescription')}
            stickyActionColumn={false}
            headClassName={{
              name: 'min-w-[180px]',
              code: 'min-w-[180px]',
              path: 'min-w-[180px]',
              sort: 'w-[72px] min-w-[72px]',
              visible: 'w-[72px] min-w-[72px]',
            }}
            cellClassName={{
              name: 'min-w-[180px]',
              code: 'min-w-[180px]',
              path: 'min-w-[180px]',
              sort: 'w-[72px] min-w-[72px]',
              visible: 'w-[72px] min-w-[72px]',
            }}
          />
          <p className='mt-3 text-xs text-muted-foreground'>{t('menus.hint')}</p>
        </CardContent></Card>
      </div>

      <Dialog open={dialogOpen} onOpenChange={requestDialogOpen}>
        <DialogContent className='sm:max-w-md'>
          <DialogHeader>
            <DialogTitle>{formID ? t('menus.dialog.editTitle') : t('menus.new')}</DialogTitle>
            <DialogDescription>
              {formID ? t('menus.dialog.editDesc') : t('menus.dialog.createDesc')}
            </DialogDescription>
          </DialogHeader>
          <FieldGroup>
            <Field>
              <FieldLabel htmlFor='menu-name'>{t('menus.form.name')}</FieldLabel>
              <Input
                id='menu-name'
                placeholder={t('menus.form.namePlaceholder')}
                aria-invalid={Boolean(errors.name)}
                {...register('name')}
              />
              <FieldError errors={[errors.name]} />
            </Field>
            <div className='grid grid-cols-2 gap-3'>
              <Field>
                <FieldLabel htmlFor='menu-code'>{t('menus.form.code')}</FieldLabel>
                <Input
                  id='menu-code'
                  placeholder='org:users'
                  aria-invalid={Boolean(errors.code)}
                  {...register('code')}
                />
                <FieldError errors={[errors.code]} />
              </Field>
              <Field>
                <FieldLabel htmlFor='menu-sort'>{t('menus.table.sort')}</FieldLabel>
                <Input
                  id='menu-sort'
                  type='number'
                  aria-invalid={Boolean(errors.sort)}
                  {...register('sort')}
                />
                <FieldError errors={[errors.sort]} />
              </Field>
            </div>
            {!formID ? (
              <Field>
                <FieldLabel>{t('menus.form.type')}</FieldLabel>
                <Controller control={control} name='type' render={({ field }) => <Select value={field.value} onValueChange={field.onChange}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectGroup><SelectItem value='group'>{t('menus.type.group')}</SelectItem><SelectItem value='page'>{t('menus.type.page')}</SelectItem></SelectGroup></SelectContent></Select>} />
              </Field>
            ) : null}
            {formType === 'page' ? (
              <>
                <Field>
                  <FieldLabel>{t('menus.form.parent')}</FieldLabel>
                  <Controller control={control} name='parentId' render={({ field }) => <Select value={field.value} onValueChange={field.onChange}><SelectTrigger aria-invalid={Boolean(errors.parentId)}><SelectValue /></SelectTrigger><SelectContent><SelectGroup>{parentOptions.map((menu) => (
                        <SelectItem key={menu.id} value={menu.id}>
                          {menuLabel(menu)}
                        </SelectItem>
                      ))}</SelectGroup></SelectContent></Select>} />
                  <FieldError errors={[errors.parentId]} />
                </Field>
                <Field>
                  <FieldLabel htmlFor='menu-path'>{t('menus.form.path')}</FieldLabel>
                  <Input
                    id='menu-path'
                    placeholder='/admin/security/accounts'
                    aria-invalid={Boolean(errors.path)}
                    {...register('path')}
                  />
                  <FieldError errors={[errors.path]} />
                </Field>
              </>
            ) : null}
          </FieldGroup>
          <FieldError errors={[errors.root]} />
          <DialogFooter>
            <Button variant='outline' onClick={() => requestDialogOpen(false)}>
              {t('common.cancel')}
            </Button>
            <Button variant='primary-glow' disabled={createMenuMut.isPending || updateMenuMut.isPending} onClick={handleSubmit(submit)}>
              {formID ? t('common.save') : t('common.create')}
            </Button>
          </DialogFooter>
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
            <AlertDialogAction onClick={() => { setDiscardOpen(false); closeForm() }}>{t('forms.discard.action')}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <DestructiveConfirmationDialog
        open={deleting !== null}
        title={t('common.deleteTitle', { name: deleting ? displayText(t, deleting.name) : '' })}
        description={t('menus.delete.desc')}
        confirmLabel={t('common.delete')}
        cancelLabel={t('common.cancel')}
        pending={deleteMenuMut.isPending}
        onOpenChange={(open) => { if (!open) setDeleting(null) }}
        onConfirm={() => void confirmDelete()}
      />
    </PageShell>
  )
}
