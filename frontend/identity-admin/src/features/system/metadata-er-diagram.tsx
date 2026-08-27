import { useEffect, useMemo, useRef } from 'react'
import dagre from '@dagrejs/dagre'
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type ReactFlowInstance,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ArrowRight, KeyRound, Link2, TableProperties } from 'lucide-react'
import { Badge } from '@domainry/ui'
import type { RuntimeObjectField, RuntimeObjectSchema } from '@/data/api'
import { useI18n } from '@/lib/i18n'
import { cn } from '@/lib/utils'

const NODE_WIDTH = 248
const NODE_BASE_HEIGHT = 92
const RELATION_ROW_HEIGHT = 25

export const RUNTIME_BUILTIN_RELATION_TARGETS = new Set(['identity_user'])

export type MetadataRelation = {
  id: string
  source: string
  target: string
  field: RuntimeObjectField
}

export type MetadataRelationDiagnostic = {
  id: string
  severity: 'error' | 'warning'
  code: 'missingTarget' | 'unknownTarget' | 'requiredSetNull' | 'oneToOneNotUnique' | 'unindexed' | 'duplicateInverse'
  objectKey: string
  fieldKey: string
  target?: string
  inverseName?: string
}

type EntityNodeData = {
  object: RuntimeObjectSchema
  relations: MetadataRelation[]
  selected: boolean
  builtInTarget: boolean
}

type EntityNode = Node<EntityNodeData, 'metadataEntity'>

function relationTarget(field: RuntimeObjectField) {
  if (field.type !== 'relation') return ''
  const sources = [field.validation, field.config]
  for (const source of sources) {
    if (!source) continue
    for (const key of ['target', 'target_object', 'object_key', 'object']) {
      const value = source[key]
      if (typeof value === 'string' && value.trim()) return value.trim()
    }
  }
  return ''
}

export function metadataRelations(objects: RuntimeObjectSchema[]): MetadataRelation[] {
  const objectKeys = new Set(objects.map((object) => object.key))
  return objects.flatMap((object) => object.fields.flatMap((field) => {
    const target = relationTarget(field)
    if (!target || (!objectKeys.has(target) && !RUNTIME_BUILTIN_RELATION_TARGETS.has(target))) return []
    return [{ id: `${object.key}:${field.key}->${target}`, source: object.key, target, field }]
  }))
}

export function isMetadataRelationTarget(objects: RuntimeObjectSchema[], target: string) {
  return RUNTIME_BUILTIN_RELATION_TARGETS.has(target) || objects.some((object) => object.key === target)
}

export function metadataRelationDiagnostics(objects: RuntimeObjectSchema[]): MetadataRelationDiagnostic[] {
  const objectKeys = new Set(objects.map((object) => object.key))
  const diagnostics: MetadataRelationDiagnostic[] = []
  const inverseOwners = new Map<string, string>()
  objects.forEach((object) => object.fields.filter((field) => field.type === 'relation').forEach((field) => {
    const target = relationTarget(field)
    const base = { objectKey: object.key, fieldKey: field.key, target }
    if (!target) diagnostics.push({ ...base, id: `${object.key}.${field.key}:missing-target`, severity: 'error', code: 'missingTarget' })
    else if (!objectKeys.has(target) && !RUNTIME_BUILTIN_RELATION_TARGETS.has(target)) diagnostics.push({ ...base, id: `${object.key}.${field.key}:unknown-target`, severity: 'error', code: 'unknownTarget' })
    if (field.required && field.config?.on_delete === 'set_null') diagnostics.push({ ...base, id: `${object.key}.${field.key}:required-set-null`, severity: 'error', code: 'requiredSetNull' })
    if (field.config?.cardinality === 'one_to_one' && !field.unique) diagnostics.push({ ...base, id: `${object.key}.${field.key}:not-unique`, severity: 'error', code: 'oneToOneNotUnique' })
    if (field.config?.indexed === false) diagnostics.push({ ...base, id: `${object.key}.${field.key}:unindexed`, severity: 'warning', code: 'unindexed' })
    const inverseName = String(field.config?.inverse_name ?? '').trim()
    if (target && inverseName) {
      const inverseKey = `${target}.${inverseName}`
      const owner = inverseOwners.get(inverseKey)
      if (owner) diagnostics.push({ ...base, inverseName, id: `${object.key}.${field.key}:duplicate-inverse`, severity: 'error', code: 'duplicateInverse' })
      else inverseOwners.set(inverseKey, `${object.key}.${field.key}`)
    }
  }))
  return diagnostics
}

function EntityNodeView({ data }: NodeProps<EntityNode>) {
  const { t } = useI18n()
  const scalarCount = data.object.fields.length - data.relations.length
  const objectLabel = data.builtInTarget && data.object.key === 'identity_user'
    ? t('metadata.er.identityUser')
    : data.object.label || data.object.name || data.object.key
  return <div className={cn(
    'w-[248px] overflow-hidden rounded-md border-2 bg-background shadow-sm transition-[border-color,box-shadow]',
    data.selected ? 'border-primary shadow-md' : 'border-border'
  )}>
    <Handle type='target' position={Position.Left} className='!size-2.5 !border-2 !border-background !bg-muted-foreground' />
    <div className={cn('flex items-center gap-2.5 border-b px-3 py-2.5', data.selected ? 'bg-primary/8' : 'bg-muted/35')}>
      <span className={cn('flex size-8 shrink-0 items-center justify-center rounded border bg-background text-muted-foreground', data.selected && 'border-primary/30 text-primary')}><TableProperties className='size-4' /></span>
      <div className='min-w-0 flex-1'><p className='truncate text-sm font-semibold'>{objectLabel}</p><code className='block truncate text-[10px] text-muted-foreground'>{data.object.key}</code></div>
      <Badge variant='secondary' className='num shrink-0 px-1.5 text-[10px]'>{data.builtInTarget ? t('metadata.er.runtimeBuiltIn') : data.object.fields.length}</Badge>
    </div>
    {data.relations.length ? <ul className='divide-y'>
      {data.relations.map((relation) => <li key={relation.id} className='flex h-[25px] items-center gap-1.5 px-3 text-[10px]'>
        <Link2 className='size-3 shrink-0 text-primary' />
        <span className='min-w-0 flex-1 truncate font-mono'>{relation.field.key}</span>
        {relation.field.required ? <span className='size-1.5 shrink-0 rounded-full bg-destructive' title='required' /> : null}
        <ArrowRight className='size-3 shrink-0 text-muted-foreground' />
        <code className='max-w-24 truncate text-muted-foreground'>{relation.target}</code>
      </li>)}
    </ul> : <div className='flex h-[34px] items-center gap-2 px-3 text-[10px] text-muted-foreground'><KeyRound className='size-3' />{t('metadata.er.noOutgoing')}</div>}
    <div className='border-t px-3 py-1.5 text-[10px] text-muted-foreground'>{data.builtInTarget ? t('metadata.er.builtInSummary') : t('metadata.er.nodeSummary', { fields: scalarCount, relations: data.relations.length })}</div>
    <Handle type='source' position={Position.Right} className='!size-2.5 !border-2 !border-background !bg-primary' />
  </div>
}

const nodeTypes = { metadataEntity: EntityNodeView }

function diagramElements(objects: RuntimeObjectSchema[], selectedObjectKey: string) {
  const relations = metadataRelations(objects)
  const objectKeys = new Set(objects.map((object) => object.key))
  const builtInTargets: RuntimeObjectSchema[] = [...new Set(relations.map((relation) => relation.target))]
    .filter((target) => !objectKeys.has(target) && RUNTIME_BUILTIN_RELATION_TARGETS.has(target))
    .map((target) => ({ key: target, name: target, fields: [] }))
  const diagramObjects = [...objects, ...builtInTargets]
  const outgoing = new Map<string, MetadataRelation[]>()
  relations.forEach((relation) => outgoing.set(relation.source, [...(outgoing.get(relation.source) ?? []), relation]))

  const graph = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}))
  graph.setGraph({ rankdir: 'LR', ranksep: 110, nodesep: 42, edgesep: 24, marginx: 32, marginy: 32 })
  diagramObjects.forEach((object) => graph.setNode(object.key, {
    width: NODE_WIDTH,
    height: NODE_BASE_HEIGHT + Math.max(1, outgoing.get(object.key)?.length ?? 0) * RELATION_ROW_HEIGHT,
  }))
  relations.forEach((relation) => graph.setEdge(relation.source, relation.target))
  dagre.layout(graph)

  const nodes: EntityNode[] = diagramObjects.map((object) => {
    const position = graph.node(object.key) as { x: number; y: number; width: number; height: number }
    const builtInTarget = !objectKeys.has(object.key)
    return {
      id: object.key,
      type: 'metadataEntity',
      position: { x: position.x - position.width / 2, y: position.y - position.height / 2 },
      data: { object, relations: outgoing.get(object.key) ?? [], selected: object.key === selectedObjectKey, builtInTarget },
      draggable: false,
      selectable: !builtInTarget,
      ariaLabel: `${object.label || object.name || object.key}: ${object.fields.length} fields, ${(outgoing.get(object.key) ?? []).length} relations`,
    }
  })
  const edges: Edge[] = relations.map((relation) => ({
    id: relation.id,
    source: relation.source,
    target: relation.target,
    type: 'smoothstep',
    label: `${relation.field.key}${relation.field.required ? ' *' : ''}`,
    markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: 'var(--primary)' },
    style: { stroke: 'var(--primary)', strokeWidth: relation.field.required ? 2 : 1.4, opacity: relation.field.required ? 0.82 : 0.52 },
    labelStyle: { fill: 'var(--muted-foreground)', fontSize: 10, fontFamily: 'var(--font-mono)' },
    labelBgStyle: { fill: 'var(--background)', fillOpacity: 0.92 },
    labelBgPadding: [4, 2],
    labelBgBorderRadius: 3,
    animated: relation.source === selectedObjectKey || relation.target === selectedObjectKey,
    data: { fieldKey: relation.field.key, required: relation.field.required, relation },
  }))
  return { nodes, edges }
}

export function MetadataERDiagram({ objects, selectedObjectKey, onSelectObject, onSelectRelation }: { objects: RuntimeObjectSchema[]; selectedObjectKey: string; onSelectObject: (key: string) => void; onSelectRelation: (relation: MetadataRelation) => void }) {
  const instance = useRef<ReactFlowInstance<EntityNode, Edge> | null>(null)
  const { nodes, edges } = useMemo(() => diagramElements(objects, selectedObjectKey), [objects, selectedObjectKey])

  useEffect(() => {
    if (!selectedObjectKey || !instance.current) return
    const selected = nodes.find((node) => node.id === selectedObjectKey)
    if (!selected) return
    void instance.current.fitView({ nodes: [selected], padding: 1.6, minZoom: 0.55, maxZoom: 1, duration: 220 })
  }, [nodes, selectedObjectKey])

  return <div className='relative h-[min(68vh,720px)] min-h-[520px]' data-testid='metadata-er-diagram'>
    <ReactFlow<EntityNode, Edge>
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      onInit={(flow) => { instance.current = flow }}
      onNodeClick={(_, node) => { if (!node.data.builtInTarget) onSelectObject(node.id) }}
      onEdgeClick={(_, edge) => { const relation = edge.data?.relation as MetadataRelation | undefined; if (relation) onSelectRelation(relation) }}
      fitView
      fitViewOptions={{ padding: 0.18, minZoom: 0.35, maxZoom: 1 }}
      minZoom={0.2}
      maxZoom={1.5}
      nodesConnectable={false}
      nodesDraggable={false}
      elementsSelectable
    >
      <Background gap={24} size={1} color='var(--border)' />
      <Controls position='bottom-left' showInteractive={false} />
      <MiniMap position='bottom-right' pannable zoomable nodeStrokeWidth={2} nodeColor={(node) => node.id === selectedObjectKey ? 'var(--primary)' : 'var(--muted)'} maskColor='color-mix(in oklab, var(--background) 82%, transparent)' />
    </ReactFlow>
  </div>
}
