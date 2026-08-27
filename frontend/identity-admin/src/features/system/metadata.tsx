import { useEffect, useMemo, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Controller, useForm } from 'react-hook-form'
import {
  AlertTriangle,
  AlignLeft,
  ArrowRightLeft,
  Braces,
  Calendar,
  CalendarClock,
  CheckCircle2,
  CircleDashed,
  Database,
  Hash,
  Link2,
  Mail,
  Network,
  Pencil,
  Phone,
  Plus,
  RefreshCw,
  Search,
  TableProperties,
  Trash2,
  ToggleLeft,
  Type,
  Rows3,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
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
  SelectGroup,
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
  ToggleGroup,
  ToggleGroupItem,
  Textarea,
} from '@domainry/ui'
import { DATA_TABLE_ACTION_CELL_CLASS, DATA_TABLE_ACTION_HEAD_CLASS, DATA_TABLE_TOOLBAR_CONTROL_CLASS, DataTableRowActions } from '@/components/data-table'
import { DestructiveConfirmationDialog } from '@/components/destructive-confirmation-dialog'
import { PageShell } from '@/components/page-shell'
import { PageQueryState } from '@/components/page-query-state'
import { StatusBadge } from '@/components/status-badge'
import { systemChangePlansApi } from '@/data/action-definition-api'
import { authoringParameter, metadataApi, objectsApi, platformCapabilitiesApi, type RuntimeObjectField, type RuntimeObjectSchema } from '@/data/api'
import { useI18n } from '@/lib/i18n'
import { usePermissions } from '@/lib/permissions'
import { cn } from '@/lib/utils'
import { runtimeApiError } from '@/lib/runtime-api'
import { runtimeErrorConstraintMessage } from '@/lib/runtime-error-details'
import { metadataFieldControl } from './metadata-field-error'
import { MetadataERDiagram, RUNTIME_BUILTIN_RELATION_TARGETS, isMetadataRelationTarget, metadataRelationDiagnostics, metadataRelations } from './metadata-er-diagram'

const FIELD_TYPE_ICONS: Record<string, LucideIcon> = {
  text: Type,
  long_text: AlignLeft,
  number: Hash,
  boolean: ToggleLeft,
  date: Calendar,
  datetime: CalendarClock,
  email: Mail,
  phone: Phone,
  url: Link2,
  json: Braces,
  relation: ArrowRightLeft,
}

const DEVELOPED_METADATA_FIELD_TYPES = new Set(['boolean', 'currency', 'date', 'datetime', 'email', 'json', 'long_text', 'number', 'percent', 'phone', 'relation', 'select', 'text', 'url', 'user'])

function initialMetadataTarget() {
  if (typeof window === 'undefined') return { objectKey: '', fieldKey: '' }
  const query = new URLSearchParams(window.location.search)
  const resourceType = query.get('resource_type')
  const resourceKey = query.get('resource_key') ?? ''
  if (resourceType === 'field') {
    const separator = resourceKey.indexOf('.')
    return separator > 0
      ? { objectKey: resourceKey.slice(0, separator), fieldKey: resourceKey.slice(separator + 1) }
      : { objectKey: '', fieldKey: '' }
  }
  return { objectKey: resourceType === 'object' ? resourceKey : '', fieldKey: '' }
}

function FieldTypeBadge({ type }: { type: string }) {
  const Icon = FIELD_TYPE_ICONS[type] ?? CircleDashed
  return (
    <Badge variant='outline' className='gap-1 font-mono text-[11px] font-normal text-muted-foreground'>
      <Icon className='size-3' />
      {type}
    </Badge>
  )
}

function metadataDefaultValue(type: string, raw: string) {
  if (raw === '') return undefined
  if (type === 'number') return Number(raw)
  if (type === 'boolean') return raw === 'true'
  if (type === 'json') return JSON.parse(raw)
  return raw
}

function FieldDefinitionDialog({
  object,
  objects,
  field,
  supportedFieldTypes,
  unsupportedFieldTypes,
  relationCardinalities,
  relationDeletePolicies,
  relationCardinalityDefault,
  relationDeletePolicyDefault,
  recordCount,
  recordCountError,
  definitionError,
  saving,
  onClose,
  onRetryRecordCount,
  onRetryDefinition,
  onSave,
}: {
  object: RuntimeObjectSchema
  objects: RuntimeObjectSchema[]
  field?: RuntimeObjectField
  supportedFieldTypes: string[]
  unsupportedFieldTypes: string[]
  relationCardinalities: string[]
  relationDeletePolicies: string[]
  relationCardinalityDefault: string
  relationDeletePolicyDefault: string
  recordCount?: number
  recordCountError?: Error | null
  definitionError?: Error | null
  saving: boolean
  onClose: () => void
  onRetryRecordCount: () => void
  onRetryDefinition: () => void
  onSave: (field: RuntimeObjectField, businessReason: string) => Promise<void>
}) {
  const { t } = useI18n()
  const fieldTypes = useMemo(() => {
    if (!field?.type || supportedFieldTypes.includes(field.type)) return supportedFieldTypes
    return [...supportedFieldTypes, field.type]
  }, [field?.type, supportedFieldTypes])
  const formSchema = useMemo(() => z.object({
    key: z.string().trim().min(1, t('metadata.field.validation.keyRequired')).regex(/^[a-z][a-z0-9_]*$/, t('metadata.field.validation.keyFormat')),
    name: z.string().trim().min(1, t('metadata.field.validation.nameRequired')),
    type: z.string().refine((value) => fieldTypes.includes(value), t('metadata.field.validation.typeRequired')),
    required: z.boolean(),
    defaultValue: z.string(),
    targetObject: z.string(),
    cardinality: z.string().refine((value) => relationCardinalities.includes(value), t('metadata.relation.validation.cardinalityRequired')),
    onDelete: z.string().refine((value) => relationDeletePolicies.includes(value), t('metadata.relation.validation.onDeleteRequired')),
    inverseName: z.string(),
    indexed: z.boolean(),
    businessReason: z.string().trim().min(1, t('metadata.field.validation.businessReasonRequired')),
  }).superRefine((values, context) => {
    if (!field && object.fields.some((candidate) => candidate.key === values.key)) {
      context.addIssue({ code: 'custom', path: ['key'], message: t('metadata.field.validation.keyUnique') })
    }
    if (!field && (recordCount ?? 0) > 0 && values.required && values.defaultValue === '') {
      context.addIssue({ code: 'custom', path: ['defaultValue'], message: t('metadata.field.validation.defaultRequired', { count: recordCount ?? 0 }) })
    }
    if (values.type === 'json' && values.defaultValue) {
      try { JSON.parse(values.defaultValue) } catch { context.addIssue({ code: 'custom', path: ['defaultValue'], message: t('metadata.field.validation.jsonDefault') }) }
    }
    if (values.type === 'relation') {
      if (!isMetadataRelationTarget(objects, values.targetObject)) context.addIssue({ code: 'custom', path: ['targetObject'], message: t('metadata.relation.validation.targetRequired') })
      if (values.onDelete === 'set_null' && values.required) context.addIssue({ code: 'custom', path: ['onDelete'], message: t('metadata.relation.validation.setNullRequired') })
      if (values.inverseName && !/^[a-z][a-z0-9_]*$/.test(values.inverseName)) context.addIssue({ code: 'custom', path: ['inverseName'], message: t('metadata.relation.validation.inverseFormat') })
    }
  }), [field, fieldTypes, object.fields, objects, recordCount, relationCardinalities, relationDeletePolicies, t])
  type Values = z.input<typeof formSchema>
  const { control, register, handleSubmit, setError, watch, formState: { errors } } = useForm<Values>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      key: field?.key ?? '',
      name: field?.name || field?.label || '',
      type: field?.type || 'text',
      required: Boolean(field?.required),
      defaultValue: field?.default_value === undefined && field?.default === undefined ? '' : JSON.stringify(field.default_value ?? field.default).replace(/^"|"$/g, ''),
      targetObject: String(field?.validation?.target ?? field?.config?.target ?? field?.config?.object_key ?? ''),
      cardinality: String(field?.config?.cardinality ?? relationCardinalityDefault),
      onDelete: String(field?.config?.on_delete ?? relationDeletePolicyDefault),
      inverseName: String(field?.config?.inverse_name ?? ''),
      indexed: field?.config?.indexed !== false,
      businessReason: '',
    },
  })
  const nextType = watch('type')
  const typeChanged = Boolean(field && nextType !== field.type)
  const selectedTypeUnsupported = !DEVELOPED_METADATA_FIELD_TYPES.has(nextType)

  const submit = async (values: Values) => {
    try {
      const defaultValue = metadataDefaultValue(values.type, values.defaultValue)
      await onSave({
        ...field,
        key: values.key.trim(),
        name: values.name.trim(),
        type: values.type,
        required: values.required,
        default: defaultValue,
        default_value: defaultValue,
        unique: values.type === 'relation' ? values.cardinality === 'one_to_one' : field?.unique,
        validation: values.type === 'relation' ? { ...(field?.validation ?? {}), target: values.targetObject } : field?.validation,
        config: values.type === 'relation' ? {
          ...(field?.config ?? {}),
          target: values.targetObject,
          cardinality: values.cardinality,
          on_delete: values.onDelete,
          inverse_name: values.inverseName.trim(),
          indexed: values.cardinality === 'one_to_one' ? true : values.indexed,
        } : field?.config ?? {},
      }, values.businessReason)
    } catch (error) {
      const structured = runtimeApiError(error)
      const control = metadataFieldControl(structured?.fieldPath ?? '')
      setError(control ?? 'root', { message: runtimeErrorConstraintMessage(t, structured, error instanceof Error ? error.message : t('dataTable.errorDescription')) })
    }
  }

  return (
    <Dialog open onOpenChange={(open) => (!open ? onClose() : null)}>
      <DialogContent className='max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg'>
        <DialogHeader>
          <DialogTitle>{field ? t('metadata.field.editTitle') : t('metadata.field.createTitle')}</DialogTitle>
          <DialogDescription>{t('metadata.field.dialogDesc', { object: object.label || object.name || object.key, count: recordCount ?? 0 })}</DialogDescription>
        </DialogHeader>
        {typeChanged ? <Alert><AlertTriangle /><AlertTitle>{t('metadata.field.typeImpactTitle')}</AlertTitle><AlertDescription>{t('metadata.field.typeImpactDesc', { from: field?.type ?? '', to: nextType, count: recordCount ?? 0 })}</AlertDescription></Alert> : null}
        {unsupportedFieldTypes.length ? <Alert data-testid='metadata-field-type-compatibility-gap'><AlertTriangle /><AlertTitle>{t('metadata.field.compatibilityGapTitle')}</AlertTitle><AlertDescription>{t('metadata.field.compatibilityGapDescription', { types: unsupportedFieldTypes.join(', ') })}</AlertDescription></Alert> : null}
        {recordCountError ? <Alert variant='destructive'><AlertTitle>{t('metadata.field.recordCountErrorTitle')}</AlertTitle><AlertDescription className='flex flex-wrap items-center justify-between gap-2'><span>{t('metadata.field.recordCountErrorDescription')}</span><Button size='sm' variant='outline' onClick={onRetryRecordCount}>{t('common.retry')}</Button></AlertDescription></Alert> : null}
        {definitionError ? <Alert variant='destructive'><AlertTitle>{t('metadata.field.definitionErrorTitle')}</AlertTitle><AlertDescription className='flex flex-wrap items-center justify-between gap-2'><span>{t('metadata.field.definitionErrorDescription')}</span><Button size='sm' variant='outline' onClick={onRetryDefinition}>{t('common.retry')}</Button></AlertDescription></Alert> : null}
        {recordCount === undefined && !recordCountError ? <div className='space-y-2' aria-label={t('metadata.field.loadingContext')}><Skeleton className='h-4 w-2/3' /><Skeleton className='h-4 w-1/2' /></div> : null}
        <FieldGroup>
          <Field data-invalid={Boolean(errors.key)}><FieldLabel htmlFor='metadata-field-key'>{t('metadata.field.key')}</FieldLabel><Input id='metadata-field-key' disabled={Boolean(field)} aria-invalid={Boolean(errors.key)} {...register('key')} /><FieldError errors={[errors.key]} /></Field>
          <Field data-invalid={Boolean(errors.name)}><FieldLabel htmlFor='metadata-field-name'>{t('metadata.field.name')}</FieldLabel><Input id='metadata-field-name' aria-invalid={Boolean(errors.name)} {...register('name')} /><FieldError errors={[errors.name]} /></Field>
          <Field><FieldLabel>{t('metadata.field.type')}</FieldLabel><Controller control={control} name='type' render={({ field: input }) => <Select value={input.value} onValueChange={input.onChange}><SelectTrigger className='w-full' data-testid='metadata-field-type'><SelectValue /></SelectTrigger><SelectContent><SelectGroup>{fieldTypes.map((type) => <SelectItem key={type} value={type}>{type}</SelectItem>)}</SelectGroup></SelectContent></Select>} /></Field>
          {nextType === 'relation' ? <>
            <Field data-invalid={Boolean(errors.targetObject)}><FieldLabel>{t('metadata.relation.target')}</FieldLabel><Controller control={control} name='targetObject' render={({ field: input }) => <Select value={input.value} onValueChange={input.onChange}><SelectTrigger className='w-full' data-testid='metadata-relation-target' aria-invalid={Boolean(errors.targetObject)}><SelectValue placeholder={t('metadata.relation.selectTarget')} /></SelectTrigger><SelectContent><SelectGroup>{[...RUNTIME_BUILTIN_RELATION_TARGETS].filter((target) => !objects.some((candidate) => candidate.key === target)).map((target) => <SelectItem key={target} value={target}>{target === 'identity_user' ? t('metadata.er.identityUser') : target} · {target}</SelectItem>)}{objects.map((candidate) => <SelectItem key={candidate.key} value={candidate.key}>{candidate.label || candidate.name || candidate.key} · {candidate.key}</SelectItem>)}</SelectGroup></SelectContent></Select>} /><FieldError errors={[errors.targetObject]} /></Field>
            <div className='grid gap-3 sm:grid-cols-2'>
              <Field><FieldLabel>{t('metadata.relation.cardinality')}</FieldLabel><Controller control={control} name='cardinality' render={({ field: input }) => <Select value={input.value} onValueChange={input.onChange}><SelectTrigger className='w-full' data-testid='metadata-relation-cardinality'><SelectValue /></SelectTrigger><SelectContent>{relationCardinalities.map((value) => <SelectItem key={value} value={value}>{value === 'many_to_one' ? t('metadata.relation.manyToOne') : value === 'one_to_one' ? t('metadata.relation.oneToOne') : value}</SelectItem>)}</SelectContent></Select>} /></Field>
              <Field data-invalid={Boolean(errors.onDelete)}><FieldLabel>{t('metadata.relation.onDelete')}</FieldLabel><Controller control={control} name='onDelete' render={({ field: input }) => <Select value={input.value} onValueChange={input.onChange}><SelectTrigger className='w-full' data-testid='metadata-relation-on-delete' aria-invalid={Boolean(errors.onDelete)}><SelectValue /></SelectTrigger><SelectContent>{relationDeletePolicies.map((value) => <SelectItem key={value} value={value}>{value === 'restrict' ? t('metadata.relation.restrict') : value === 'set_null' ? t('metadata.relation.setNull') : value === 'cascade' ? t('metadata.relation.cascade') : value}</SelectItem>)}</SelectContent></Select>} /><FieldError errors={[errors.onDelete]} /></Field>
            </div>
            <Field data-invalid={Boolean(errors.inverseName)}><FieldLabel htmlFor='metadata-relation-inverse'>{t('metadata.relation.inverseName')}</FieldLabel><Input id='metadata-relation-inverse' placeholder={t('metadata.relation.inversePlaceholder')} aria-invalid={Boolean(errors.inverseName)} {...register('inverseName')} /><FieldError errors={[errors.inverseName]} /></Field>
            <Field orientation='horizontal'><div className='flex-1'><FieldLabel>{t('metadata.relation.indexed')}</FieldLabel><p className='text-xs text-muted-foreground'>{t('metadata.relation.indexedDesc')}</p></div><Controller control={control} name='indexed' render={({ field: input }) => <Switch disabled={watch('cardinality') === 'one_to_one'} checked={watch('cardinality') === 'one_to_one' || input.value} onCheckedChange={input.onChange} />} /></Field>
            <p className='rounded-md border bg-muted/25 p-2.5 text-xs text-muted-foreground'>{t('metadata.relation.manyToManyHint')}</p>
          </> : null}
          <Field data-invalid={Boolean(errors.defaultValue)}><FieldLabel htmlFor='metadata-field-default'>{t('metadata.field.default')}</FieldLabel><Input id='metadata-field-default' aria-invalid={Boolean(errors.defaultValue)} {...register('defaultValue')} /><FieldError errors={[errors.defaultValue]} /></Field>
          <Field orientation='horizontal'><div className='flex-1'><FieldLabel>{t('metadata.field.required')}</FieldLabel><p className='text-xs text-muted-foreground'>{t('metadata.field.requiredDesc')}</p></div><Controller control={control} name='required' render={({ field: input }) => <Switch checked={input.value} onCheckedChange={input.onChange} />} /></Field>
          <Field data-invalid={Boolean(errors.businessReason)}><FieldLabel htmlFor='metadata-field-business-reason'>{t('metadata.field.businessReason')}</FieldLabel><Textarea id='metadata-field-business-reason' rows={3} placeholder={t('metadata.field.businessReasonPlaceholder')} aria-invalid={Boolean(errors.businessReason)} {...register('businessReason')} /><FieldError errors={[errors.businessReason]} /></Field>
        </FieldGroup>
        <FieldError errors={[errors.root]} />
        <DialogFooter><Button variant='outline' onClick={onClose}>{t('common.cancel')}</Button><Button disabled={saving || recordCount === undefined || Boolean(recordCountError) || Boolean(definitionError) || selectedTypeUnsupported} onClick={handleSubmit(submit)}>{saving ? t('metadata.field.savingDraft') : t('metadata.field.saveDraft')}</Button></DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export function MetadataPage() {
  const { t } = useI18n()
  const permissions = usePermissions()
  const canRead = permissions.ready && permissions.has('metadata.read')
  const canWrite = permissions.ready && permissions.has('metadata.write')
  const client = useQueryClient()
  const initialTarget = useMemo(initialMetadataTarget, [])
  const [selectedObjectKey, setSelectedObjectKey] = useState(initialTarget.objectKey)
  const [selectedFieldKey, setSelectedFieldKey] = useState(initialTarget.fieldKey)
  const [objectSearch, setObjectSearch] = useState('')
  const [viewMode, setViewMode] = useState<'fields' | 'relations'>('fields')
  const [editingField, setEditingField] = useState<RuntimeObjectField | null | undefined>(undefined)
  const [deletingField, setDeletingField] = useState<RuntimeObjectField | undefined>()
  const [deleteReason, setDeleteReason] = useState('')
  const [deleteError, setDeleteError] = useState('')
  const [savedDraft, setSavedDraft] = useState<{ planID: string; revision: number; status: string } | null>(null)
  const savedDraftQuery = useQuery({
    queryKey: ['runtime', 'change-plan', savedDraft?.planID],
    queryFn: () => systemChangePlansApi.get(savedDraft!.planID),
    enabled: Boolean(savedDraft?.planID),
    retry: false,
    refetchInterval: 2_000,
  })
  const currentSavedDraft = savedDraftQuery.data
    ? { planID: savedDraftQuery.data.plan_id, revision: savedDraftQuery.data.revision, status: savedDraftQuery.data.status }
    : savedDraft
  const query = useQuery({
    queryKey: ['runtime', 'metadata', 'overview'],
    queryFn: objectsApi.schemaSnapshot,
    enabled: canRead,
  })
  const migrationQuery = useQuery({
    queryKey: ['runtime', 'metadata', 'migration-plan'],
    queryFn: metadataApi.migrationPlan,
    enabled: canRead,
  })
  const capabilitiesQuery = useQuery({
    queryKey: ['runtime', 'metadata', 'authoring-capabilities'],
    queryFn: platformCapabilitiesApi.get,
    enabled: canRead,
  })
  const saveField = useMutation({
	mutationFn: ({ objectKey, field, businessReason, current }: { objectKey: string; field: RuntimeObjectField; businessReason: string; current?: RuntimeObjectField }) => metadataApi.publishField(objectKey, field, businessReason, current),
    onSuccess: async (draft) => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ['runtime', 'change-plan', draft.plan_id] }),
        client.invalidateQueries({ queryKey: ['runtime', 'domain-reference-graph'] }),
      ])
      setSavedDraft({ planID: draft.plan_id, revision: draft.revision, status: draft.status })
      setEditingField(undefined)
      toast.success(t('metadata.field.draftSaved'))
    },
  })
  const deleteField = useMutation({
    mutationFn: ({ objectKey, field, businessReason }: { objectKey: string; field: RuntimeObjectField; businessReason: string }) =>
      metadataApi.deleteField(objectKey, field, businessReason),
    onSuccess: async (draft) => {
      await Promise.all([
        client.invalidateQueries({ queryKey: ['runtime', 'change-plan', draft.plan_id] }),
        client.invalidateQueries({ queryKey: ['runtime', 'domain-reference-graph'] }),
      ])
      setSavedDraft({ planID: draft.plan_id, revision: draft.revision, status: draft.status })
      setDeletingField(undefined)
      setDeleteReason('')
      setDeleteError('')
      toast.success(t('metadata.field.deleteDraftSaved'))
    },
    onError: (error) => {
      const structured = runtimeApiError(error)
      setDeleteError(runtimeErrorConstraintMessage(t, structured, error instanceof Error ? error.message : t('dataTable.errorDescription')))
    },
  })
  const selectedObject = query.data?.objects?.find((object) => object.key === selectedObjectKey) ?? (selectedObjectKey ? undefined : query.data?.objects?.[0])
  const editingFieldDefinitionQuery = useQuery({
    queryKey: ['runtime', 'metadata', 'field-definition', selectedObject?.key, editingField?.key],
    queryFn: () => metadataApi.fieldDefinition(selectedObject!.key, editingField!.key),
    enabled: canRead && Boolean(selectedObject && editingField),
    staleTime: 0,
  })
  const recordCountQuery = useQuery({
    queryKey: ['runtime', 'metadata', 'record-count', selectedObject?.key],
    queryFn: () => metadataApi.objectRecordCount(selectedObject!.key),
    enabled: canRead && Boolean(selectedObject && editingField !== undefined),
  })

  useEffect(() => {
    if (!query.data || selectedObjectKey) return
    const first = query.data.objects?.[0]
    if (first) setSelectedObjectKey(first.key)
  }, [query.data, selectedObjectKey])

  if (!permissions.ready) return <PageQueryState title={t('metadata.title')} description={t('metadata.desc')} />
  if (!canRead) return <PageQueryState title={t('metadata.title')} description={t('metadata.desc')} error={new Error(t('metadata.permissionDenied'))} />
  if (!query.data) return <PageQueryState title={t('metadata.title')} description={t('metadata.desc')} error={query.error} onRetry={() => void query.refetch()} />
  const schema = query.data
  const migration = migrationQuery.data ?? { count: 0, steps: [] }
  const supportedFieldTypes = capabilitiesQuery.data ? authoringParameter(capabilitiesQuery.data, 'schema.field', 'type')?.enum ?? [] : []
  const unsupportedFieldTypes = supportedFieldTypes.filter((type) => !DEVELOPED_METADATA_FIELD_TYPES.has(type))
  const editableFieldTypes = supportedFieldTypes.filter((type) => DEVELOPED_METADATA_FIELD_TYPES.has(type))
  const relationCardinality = capabilitiesQuery.data ? authoringParameter(capabilitiesQuery.data, 'schema.relation', 'cardinality') : undefined
  const relationDeletePolicy = capabilitiesQuery.data ? authoringParameter(capabilitiesQuery.data, 'schema.relation', 'on_delete') : undefined
  const relationCardinalities = relationCardinality?.enum ?? []
  const relationDeletePolicies = relationDeletePolicy?.enum ?? []
  const objects = schema.objects ?? []
  const migrationByObject = new Map(migration.steps.map((step) => [step.object_key, step]))
  const totalFields = objects.reduce((sum, object) => sum + object.fields.length, 0)
  const relations = metadataRelations(objects)
  const relationDiagnostics = metadataRelationDiagnostics(objects)
  const keyword = objectSearch.trim().toLowerCase()
  const visibleObjects = keyword
    ? objects.filter((object) =>
        [object.label, object.name, object.key].some((value) => value?.toLowerCase().includes(keyword)))
    : objects
  const selectedStep = selectedObject ? migrationByObject.get(selectedObject.key) : undefined
  const stats: Array<[string, number]> = [
    [t('metadata.stats.objects'), objects.length],
    [t('metadata.stats.fields'), totalFields],
    [t('metadata.stats.pending'), migration.count],
  ]
  const refreshing = query.isFetching || migrationQuery.isFetching || capabilitiesQuery.isFetching
  const invalidObjectTarget = Boolean(selectedObjectKey && !selectedObject)
  const invalidFieldTarget = Boolean(selectedObject && selectedFieldKey && !selectedObject.fields.some((field) => field.key === selectedFieldKey))
  const selectObject = (objectKey: string) => {
    setSelectedObjectKey(objectKey)
    setSelectedFieldKey('')
    window.history.replaceState(null, '', `/admin/system/metadata?resource_type=object&resource_key=${encodeURIComponent(objectKey)}`)
  }
  const focusField = (objectKey: string, fieldKey: string) => {
    setSelectedObjectKey(objectKey)
    setSelectedFieldKey(fieldKey)
    window.history.replaceState(null, '', `/admin/system/metadata?resource_type=field&resource_key=${encodeURIComponent(`${objectKey}.${fieldKey}`)}`)
  }

  return (
    <PageShell
      title={t('metadata.title')}
      description={t('metadata.desc')}
      actions={
        <div className='flex flex-wrap items-center gap-2'>
          <ToggleGroup type='single' variant='outline' value={viewMode} onValueChange={(value) => { if (value) setViewMode(value as 'fields' | 'relations') }} aria-label={t('metadata.view.label')}>
            <ToggleGroupItem value='fields' className='h-9 px-3'><Rows3 className='size-4' />{t('metadata.view.fields')}</ToggleGroupItem>
            <ToggleGroupItem value='relations' className='h-9 px-3'><Network className='size-4' />{t('metadata.view.relations')}</ToggleGroupItem>
          </ToggleGroup>
          <Button variant='outline' disabled={refreshing} onClick={() => void Promise.all([query.refetch(), migrationQuery.refetch(), capabilitiesQuery.refetch()])}>
            <RefreshCw className={refreshing ? 'animate-spin' : undefined} data-icon='inline-start' />{t('metadata.refresh')}
          </Button>
        </div>
      }
    >
      {currentSavedDraft && currentSavedDraft.status !== 'published' ? <Alert><CheckCircle2 /><AlertTitle>{t('metadata.field.draftSavedTitle')}</AlertTitle><AlertDescription>{t('metadata.field.draftSavedDescription', { plan: currentSavedDraft.planID, status: currentSavedDraft.status, revision: currentSavedDraft.revision })}</AlertDescription></Alert> : null}
      {invalidObjectTarget || invalidFieldTarget ? <Alert variant='destructive'><AlertTitle>{t('metadata.deepLink.notFoundTitle')}</AlertTitle><AlertDescription>{t('metadata.deepLink.notFoundDescription', { key: invalidObjectTarget ? selectedObjectKey : `${selectedObject?.key}.${selectedFieldKey}` })}</AlertDescription></Alert> : null}
      {migrationQuery.error ? <Alert variant='destructive'><AlertTitle>{t('metadata.migration.errorTitle')}</AlertTitle><AlertDescription className='flex flex-wrap items-center justify-between gap-2'><span>{t('metadata.migration.errorDescription')}</span><Button size='sm' variant='outline' onClick={() => void migrationQuery.refetch()}>{t('common.retry')}</Button></AlertDescription></Alert> : null}
      {capabilitiesQuery.error ? <Alert variant='destructive'><AlertTitle>{t('metadata.capabilities.errorTitle')}</AlertTitle><AlertDescription className='flex flex-wrap items-center justify-between gap-2'><span>{t('metadata.capabilities.errorDescription')}</span><Button size='sm' variant='outline' onClick={() => void capabilitiesQuery.refetch()}>{t('common.retry')}</Button></AlertDescription></Alert> : null}
      <Card className='relative gap-0 overflow-hidden py-0'>
        <div aria-hidden className='pointer-events-none absolute inset-0 bg-[radial-gradient(120%_180%_at_0%_0%,var(--accent)_0%,transparent_48%)] opacity-70' />
        <div className='relative flex flex-col gap-4 px-5 py-4 lg:flex-row lg:items-center lg:justify-between'>
          <div className='flex min-w-0 items-center gap-3.5'>
            <span className='flex size-11 shrink-0 items-center justify-center rounded-lg border bg-card text-primary shadow-(--card-shadow)'>
              <Database className='size-5' />
            </span>
            <div className='min-w-0'>
              <p className='truncate font-display text-lg font-extrabold tracking-tight'>
                {schema.name || schema.template_id || t('metadata.runtimeSchema')}
              </p>
              <div className='mt-1 flex flex-wrap items-center gap-1.5'>
                <Badge variant='secondary' className='font-mono text-[11px]'>
                  {t('metadata.identity.version', { version: schema.template_version || '—' })}
                </Badge>
                <code className='max-w-64 truncate rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground'>
                  {schema.schema_hash || '—'}
                </code>
              </div>
            </div>
          </div>
          <div className='grid shrink-0 grid-cols-3 gap-px overflow-hidden rounded-lg border bg-border'>
            {stats.map(([label, value]) => (
              <div key={label} className='flex flex-col gap-0.5 bg-card px-4 py-2.5 lg:min-w-30'>
                <span className='text-(length:--font-size-meta) font-medium tracking-[0.07em] uppercase text-muted-foreground'>{label}</span>
                <span className='num font-display text-xl leading-tight font-extrabold tracking-tight'>{value}</span>
              </div>
            ))}
          </div>
        </div>
      </Card>

      <div className='grid items-start gap-4 lg:grid-cols-[280px_minmax(0,1fr)]'>
        <Card className='gap-0 py-0'>
          <div className='border-b p-2.5'>
            <InputGroup className={DATA_TABLE_TOOLBAR_CONTROL_CLASS}>
              <InputGroupAddon>
                <Search className='size-4' />
              </InputGroupAddon>
              <InputGroupInput
                value={objectSearch}
                onChange={(event) => setObjectSearch(event.target.value)}
                placeholder={t('metadata.objects.search')}
                aria-label={t('metadata.objects.search')}
              />
            </InputGroup>
          </div>
          <nav className='flex max-h-130 flex-col gap-0.5 overflow-y-auto p-2' aria-label={t('metadata.table.entity')}>
            {visibleObjects.map((object) => {
              const active = selectedObject?.key === object.key
              const pending = migrationByObject.has(object.key)
              return (
                <button
                  key={object.key}
                  type='button'
                  aria-current={active ? 'true' : undefined}
                  onClick={() => selectObject(object.key)}
                  className={cn(
                    'flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-left transition-colors',
                    active ? 'bg-(--surface-selected)' : 'hover:bg-(--surface-hover)'
                  )}
                >
                  <TableProperties className={cn('size-4 shrink-0', active ? 'text-primary' : 'text-muted-foreground')} />
                  <span className='min-w-0 flex-1'>
                    <span className='block truncate text-sm font-medium'>{object.label || object.name || object.key}</span>
                    <code className='block truncate font-mono text-[11px] text-muted-foreground'>{object.key}</code>
                  </span>
                  {pending ? <span aria-hidden className='size-1.5 shrink-0 rounded-full bg-warning' /> : null}
                  <Badge variant='secondary' className='num shrink-0 px-1.5 text-[11px]'>{object.fields.length}</Badge>
                </button>
              )
            })}
            {visibleObjects.length === 0 ? (
              <p className='px-2.5 py-6 text-center text-xs text-muted-foreground'>{objects.length === 0 ? t('metadata.objects.runtimeEmpty') : t('metadata.objects.filteredEmpty')}</p>
            ) : null}
          </nav>
        </Card>

        <div className='flex min-w-0 flex-col gap-4'>
          {viewMode === 'relations' ? (
            <Card className='gap-0 overflow-hidden py-0'>
              <div className='flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3'>
                <div className='min-w-0'>
                  <div className='flex items-center gap-2'><Network className='size-4 text-primary' /><h2 className='font-display text-base font-bold tracking-tight'>{t('metadata.er.title')}</h2></div>
                  <p className='mt-1 text-xs text-muted-foreground'>{t('metadata.er.desc')}</p>
                </div>
                <div className='flex items-center gap-1.5'><Badge variant='secondary'>{t('metadata.er.entities', { count: objects.length })}</Badge><Badge variant='secondary'>{t('metadata.er.relations', { count: relations.length })}</Badge></div>
              </div>
              <MetadataERDiagram objects={objects} selectedObjectKey={selectedObject?.key ?? ''} onSelectObject={selectObject} onSelectRelation={(relation) => { focusField(relation.source, relation.field.key); if (canWrite) setEditingField(relation.field) }} />
              <div className='border-t px-4 py-3'>
                <div className='flex items-center justify-between gap-3'><div><h3 className='text-sm font-semibold'>{t('metadata.er.diagnostics')}</h3><p className='mt-0.5 text-xs text-muted-foreground'>{t('metadata.er.diagnosticsDesc')}</p></div>{relationDiagnostics.length ? <Badge variant='destructive'>{t('metadata.er.issueCount', { count: relationDiagnostics.length })}</Badge> : <StatusBadge value='success'>{t('metadata.er.healthy')}</StatusBadge>}</div>
                {relationDiagnostics.length ? <ul className='mt-3 divide-y rounded-md border'>{relationDiagnostics.map((diagnostic) => <li key={diagnostic.id} className='flex items-start gap-2.5 px-3 py-2 text-xs'><AlertTriangle className={cn('mt-0.5 size-3.5 shrink-0', diagnostic.severity === 'error' ? 'text-destructive' : 'text-warning')} /><button type='button' className='min-w-0 flex-1 text-left' onClick={() => { const object = objects.find((candidate) => candidate.key === diagnostic.objectKey); const field = object?.fields.find((candidate) => candidate.key === diagnostic.fieldKey); if (field) { setSelectedObjectKey(object!.key); setEditingField(field) } }}><code className='font-mono'>{diagnostic.objectKey}.{diagnostic.fieldKey}</code><span className='ml-2 text-muted-foreground'>{t(`metadata.er.diagnostic.${diagnostic.code}` as never, { target: diagnostic.target || '—', inverse: diagnostic.inverseName || '—' })}</span></button></li>)}</ul> : <div className='mt-3 flex items-center gap-2 text-xs text-muted-foreground'><CheckCircle2 className='size-4 text-success' />{t('metadata.er.healthyDesc')}</div>}
              </div>
              <div className='flex flex-wrap items-center gap-x-4 gap-y-1 border-t px-4 py-2 text-[11px] text-muted-foreground'><span>{t('metadata.er.requiredLegend')}</span><span>{t('metadata.er.optionalLegend')}</span><span>{t('metadata.er.interactionHint')}</span></div>
            </Card>
          ) : selectedObject ? (
            <Card className='gap-0 overflow-hidden py-0'>
              <div className='flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3'>
                <div className='min-w-0'>
                  <div className='flex items-center gap-2'>
                    <h2 className='truncate font-display text-base font-bold tracking-tight'>
                      {selectedObject.label || selectedObject.name || selectedObject.key}
                    </h2>
                    {selectedStep
                      ? <StatusBadge value='pending'>{selectedStep.operation}</StatusBadge>
                      : <StatusBadge value='success'>{t('metadata.sync.synced')}</StatusBadge>}
                  </div>
                  <div className='mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground'>
                    <span>{t('metadata.table.table')}</span>
                    <code className='rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]'>{selectedStep?.table || selectedObject.key}</code>
                    <span aria-hidden>·</span>
                    <span>{t('metadata.field.desc', { count: selectedObject.fields.length })}</span>
                  </div>
                </div>
                <Button size='sm' disabled={!canWrite || editableFieldTypes.length === 0 || capabilitiesQuery.isError} onClick={() => setEditingField(null)}>
                  <Plus data-icon='inline-start' />{t('metadata.field.add')}
                </Button>
              </div>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t('metadata.field.name')}</TableHead>
                    <TableHead>{t('metadata.field.type')}</TableHead>
                    <TableHead>{t('metadata.field.required')}</TableHead>
                    <TableHead>{t('metadata.field.default')}</TableHead>
                    <TableHead className={DATA_TABLE_ACTION_HEAD_CLASS}>{t('common.actions')}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {selectedObject.fields.map((field) => (
                    <TableRow key={field.key} className={cn('group', selectedFieldKey === field.key && 'bg-(--surface-selected)')} aria-current={selectedFieldKey === field.key ? 'true' : undefined}>
                      <TableCell>
                        <button type='button' className='text-left' onClick={() => focusField(selectedObject.key, field.key)}>
                          <span className='block font-medium'>{field.name || field.label || field.key}</span>
                          <code className='font-mono text-[11px] text-muted-foreground'>{field.key}</code>
                        </button>
                      </TableCell>
                      <TableCell><FieldTypeBadge type={field.type} />{field.type === 'relation' ? <div className='mt-1 text-[11px] text-muted-foreground'><code>{String(field.validation?.target ?? field.config?.target ?? field.config?.object_key ?? '—')}</code> · <code>{String(field.config?.cardinality ?? '—')}</code> · <code>{String(field.config?.on_delete ?? '—')}</code></div> : null}</TableCell>
                      <TableCell>
                        {field.required
                          ? <Badge variant='outline' className='px-2 text-[11px] font-medium' dot>{t('common.yes')}</Badge>
                          : <span className='text-muted-foreground'>—</span>}
                      </TableCell>
                      <TableCell>
                        <code className='font-mono text-xs'>
                          {field.default_value === undefined && field.default === undefined ? '—' : JSON.stringify(field.default_value ?? field.default)}
                        </code>
                      </TableCell>
                      <TableCell className={DATA_TABLE_ACTION_CELL_CLASS}>
                        <DataTableRowActions
                          menuLabel={t('common.actions')}
                          primary={[{
                            label: t('common.edit'),
                            ariaLabel: t('metadata.field.editAria', { name: field.name || field.label || field.key }),
                            icon: Pencil,
                            disabled: !canWrite || !DEVELOPED_METADATA_FIELD_TYPES.has(field.type),
                            onSelect: () => { focusField(selectedObject.key, field.key); setEditingField(field) },
                          }]}
                          secondary={[
                            {
                              label: t('metadata.field.inspectImpact'),
                              icon: Link2,
                              onSelect: () => { window.location.href = `/admin/system/domain-impact?resource_type=field&resource_key=${encodeURIComponent(`${selectedObject.key}.${field.key}`)}` },
                            },
                            {
                              label: t('common.delete'),
                              icon: Trash2,
                              destructive: true,
                              separatorBefore: true,
                              disabled: !canWrite,
                              onSelect: () => { setDeleteError(''); setDeleteReason(''); setDeletingField(field) },
                            },
                          ]}
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                  {selectedObject.fields.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className='py-8 text-center text-muted-foreground'>{t('metadata.field.empty')}</TableCell>
                    </TableRow>
                  ) : null}
                </TableBody>
              </Table>
            </Card>
          ) : null}

          <Card className='gap-0 overflow-hidden py-0'>
            <div className='flex items-center justify-between gap-3 border-b px-4 py-3'>
              <div>
                <h2 className='font-display text-base font-bold tracking-tight'>{t('metadata.migration.title')}</h2>
                <p className='mt-0.5 text-xs text-muted-foreground'>{t('metadata.migration.desc', { count: migration.count })}</p>
              </div>
              {migration.count > 0 ? <StatusBadge value='pending'>{migration.count}</StatusBadge> : null}
            </div>
            {migration.steps.length > 0 ? (
              <ol className='flex flex-col divide-y'>
                {migration.steps.map((step) => (
                  <li key={`${step.object_key}:${step.operation}`} className='flex items-center gap-3 px-4 py-2.5'>
                    <span className='flex size-7 shrink-0 items-center justify-center rounded-md border bg-muted text-muted-foreground'>
                      <ArrowRightLeft className='size-3.5' />
                    </span>
                    <div className='min-w-0 flex-1'>
                      <div className='flex flex-wrap items-center gap-x-2'>
                        <span className='text-sm font-medium'>{step.object_key}</span>
                        <code className='font-mono text-[11px] text-muted-foreground'>{step.table}</code>
                      </div>
                      <p className='truncate text-xs text-muted-foreground'>{step.description}</p>
                    </div>
                    <Badge variant='outline' className='shrink-0 font-mono text-[11px]'>{step.operation}</Badge>
                  </li>
                ))}
              </ol>
            ) : (
              <div className='flex items-center gap-2 px-4 py-4 text-sm text-muted-foreground'>
                <CheckCircle2 className='size-4 text-success' />
                {t('metadata.migration.empty')}
              </div>
            )}
          </Card>
        </div>
      </div>

      {selectedObject && editingField !== undefined ? (
        <FieldDefinitionDialog
          key={`${selectedObject.key}:${editingField?.key ?? 'new'}`}
          object={selectedObject}
          objects={objects}
          field={editingField ?? undefined}
          supportedFieldTypes={editableFieldTypes}
          unsupportedFieldTypes={unsupportedFieldTypes}
          relationCardinalities={relationCardinalities}
          relationDeletePolicies={relationDeletePolicies}
          relationCardinalityDefault={String(relationCardinality?.default ?? '')}
          relationDeletePolicyDefault={String(relationDeletePolicy?.default ?? '')}
          recordCount={recordCountQuery.data?.count}
          recordCountError={recordCountQuery.error}
          definitionError={editingFieldDefinitionQuery.error}
          saving={saveField.isPending || Boolean(editingField && editingFieldDefinitionQuery.isPending)}
          onClose={() => setEditingField(undefined)}
          onRetryRecordCount={() => void recordCountQuery.refetch()}
          onRetryDefinition={() => void editingFieldDefinitionQuery.refetch()}
		  onSave={(field, businessReason) => saveField.mutateAsync({ objectKey: selectedObject.key, field, businessReason, current: editingField ? editingFieldDefinitionQuery.data!.field : undefined }).then(() => undefined)}
        />
      ) : null}
      <DestructiveConfirmationDialog
        open={Boolean(selectedObject && deletingField)}
        title={t('metadata.field.deleteTitle')}
        description={t('metadata.field.deleteDescription', { field: deletingField?.key ?? '—', object: selectedObject?.key ?? '—' })}
        error={deleteError}
        confirmLabel={t('metadata.field.saveDeleteDraft')}
        cancelLabel={t('common.cancel')}
        pending={deleteField.isPending}
        reason={deleteReason}
        reasonLabel={t('metadata.field.businessReason')}
        reasonPlaceholder={t('metadata.field.deleteReasonPlaceholder')}
        reasonRequired
        onReasonChange={setDeleteReason}
        onOpenChange={(open) => {
          if (!open) {
            setDeletingField(undefined)
            setDeleteReason('')
            setDeleteError('')
          }
        }}
        onConfirm={() => {
          if (selectedObject && deletingField && deleteReason.trim()) {
            deleteField.mutate({ objectKey: selectedObject.key, field: deletingField, businessReason: deleteReason.trim() })
          }
        }}
      />
    </PageShell>
  )
}
