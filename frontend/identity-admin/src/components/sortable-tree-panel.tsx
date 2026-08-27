import { useMemo, useState, type ReactNode } from 'react'
import {
  closestCenter,
  DndContext,
  KeyboardSensor,
  PointerSensor,
  useSensor,
  useSensors,
  type DragEndEvent,
} from '@dnd-kit/core'
import {
  SortableContext,
  sortableKeyboardCoordinates,
  useSortable,
  verticalListSortingStrategy,
} from '@dnd-kit/sortable'
import { CSS } from '@dnd-kit/utilities'
import { ChevronDown, ChevronRight, FolderTree, GripVertical, Search } from 'lucide-react'
import {
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  InputGroup,
  InputGroupAddon,
  InputGroupInput,
  ScrollArea,
} from '@domainry/ui'
import { cn } from '@domainry/ui/lib/utils'
import { DATA_TABLE_TOOLBAR_CONTROL_CLASS } from '@/components/data-table'

export interface SortableTreeNode {
  id: string
  label: string
  parentId: string | null
  sort: number
  icon?: ReactNode
  disabled?: boolean
}

export interface SortableTreeMove {
  id: string
  parentId: string | null
  orderedIds: string[]
}

interface FlatTreeNode extends SortableTreeNode {
  depth: number
}

function orderedTree(nodes: SortableTreeNode[]) {
  const byParent = new Map<string | null, SortableTreeNode[]>()
  for (const node of nodes) {
    const siblings = byParent.get(node.parentId) ?? []
    siblings.push(node)
    byParent.set(node.parentId, siblings)
  }
  for (const siblings of byParent.values()) {
    siblings.sort((left, right) => left.sort - right.sort || left.label.localeCompare(right.label))
  }
  const result: FlatTreeNode[] = []
  const visit = (parentId: string | null, depth: number) => {
    for (const node of byParent.get(parentId) ?? []) {
      result.push({ ...node, depth })
      visit(node.id, depth + 1)
    }
  }
  visit(null, 0)
  return result
}

function descendants(nodes: SortableTreeNode[], id: string) {
  const result = new Set<string>()
  const collect = (parentId: string) => {
    for (const node of nodes.filter((candidate) => candidate.parentId === parentId)) {
      result.add(node.id)
      collect(node.id)
    }
  }
  collect(id)
  return result
}

export function SortableTreePanel({
  title,
  description,
  allLabel,
  dragLabel,
  searchPlaceholder,
  collapseLabel,
  expandLabel,
  nodes,
  selectedId,
  disabled = false,
  treeViewportClassName,
  onSelect,
  onMove,
  onMoveError,
}: {
  title: string
  description: string
  allLabel: string
  dragLabel: (label: string) => string
  searchPlaceholder: string
  collapseLabel: (label: string) => string
  expandLabel: (label: string) => string
  nodes: SortableTreeNode[]
  selectedId?: string
  disabled?: boolean
  treeViewportClassName?: string
  onSelect: (id?: string) => void
  onMove: (move: SortableTreeMove) => Promise<void>
  onMoveError?: (error: unknown) => void
}) {
  const [query, setQuery] = useState('')
  const [moving, setMoving] = useState(false)
  const [collapsedIds, setCollapsedIds] = useState<Set<string>>(() => new Set())
  const sensors = useSensors(
    useSensor(PointerSensor, { activationConstraint: { distance: 4 } }),
    useSensor(KeyboardSensor, { coordinateGetter: sortableKeyboardCoordinates })
  )
  const flat = useMemo(() => orderedTree(nodes), [nodes])
  const childCounts = useMemo(() => {
    const counts = new Map<string, number>()
    for (const node of nodes) {
      if (node.parentId) counts.set(node.parentId, (counts.get(node.parentId) ?? 0) + 1)
    }
    return counts
  }, [nodes])
  const visible = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    if (!normalized) {
      const byID = new Map(nodes.map((node) => [node.id, node]))
      return flat.filter((node) => {
        let parent = node.parentId ? byID.get(node.parentId) : undefined
        while (parent) {
          if (collapsedIds.has(parent.id)) return false
          parent = parent.parentId ? byID.get(parent.parentId) : undefined
        }
        return true
      })
    }
    const included = new Set<string>()
    const byID = new Map(nodes.map((node) => [node.id, node]))
    for (const node of nodes) {
      if (!node.label.toLowerCase().includes(normalized)) continue
      included.add(node.id)
      let parent = node.parentId ? byID.get(node.parentId) : undefined
      while (parent) {
        included.add(parent.id)
        parent = parent.parentId ? byID.get(parent.parentId) : undefined
      }
    }
    return flat.filter((node) => included.has(node.id))
  }, [collapsedIds, flat, nodes, query])

  const toggleCollapsed = (id: string) => {
    setCollapsedIds((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleDragEnd = async ({ active, over, delta }: DragEndEvent) => {
    if (!over || active.id === over.id) return
    const activeNode = nodes.find((node) => node.id === active.id)
    const overNode = nodes.find((node) => node.id === over.id)
    if (!activeNode || !overNode) return
    const blocked = descendants(nodes, activeNode.id)
    let parentId = overNode.parentId
    if (delta.x > 32) parentId = overNode.id
    if (delta.x < -32 && overNode.parentId) {
      parentId = nodes.find((node) => node.id === overNode.parentId)?.parentId ?? null
    }
    if (parentId === activeNode.id || (parentId && blocked.has(parentId))) return

    const siblings = nodes
      .filter((node) => node.id !== activeNode.id && node.parentId === parentId)
      .sort((left, right) => left.sort - right.sort || left.label.localeCompare(right.label))
    const overIndex = siblings.findIndex((node) => node.id === overNode.id)
    const insertAt = parentId === overNode.id ? siblings.length : Math.max(0, overIndex)
    const orderedIds = siblings.map((node) => node.id)
    orderedIds.splice(insertAt, 0, activeNode.id)

    setMoving(true)
    try {
      await onMove({ id: activeNode.id, parentId, orderedIds })
    } catch (error) {
      onMoveError?.(error)
    } finally {
      setMoving(false)
    }
  }

  const treeContent = (
    <DndContext sensors={sensors} collisionDetection={closestCenter} onDragEnd={handleDragEnd}>
      <SortableContext items={visible.map((node) => node.id)} strategy={verticalListSortingStrategy}>
        <div role='tree' className='flex flex-col gap-1'>
          {visible.map((node) => (
            <SortableTreeRow
              key={node.id}
              node={node}
              selected={selectedId === node.id}
              draggingDisabled={disabled || moving || Boolean(query) || Boolean(node.disabled)}
              dragLabel={dragLabel(node.label)}
              hasChildren={(childCounts.get(node.id) ?? 0) > 0}
              collapsed={!query && collapsedIds.has(node.id)}
              collapseLabel={collapseLabel(node.label)}
              expandLabel={expandLabel(node.label)}
              onToggle={() => toggleCollapsed(node.id)}
              onSelect={() => onSelect(node.id)}
            />
          ))}
        </div>
      </SortableContext>
    </DndContext>
  )

  return (
    <Card>
      <CardHeader>
        <CardTitle className='flex items-center gap-2 text-base'>
          <FolderTree />
          {title}
        </CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className='flex flex-col gap-2'>
        <InputGroup className={DATA_TABLE_TOOLBAR_CONTROL_CLASS}>
          <InputGroupAddon><Search /></InputGroupAddon>
          <InputGroupInput value={query} onChange={(event) => setQuery(event.target.value)} placeholder={searchPlaceholder} />
        </InputGroup>
        <Button type='button' variant={selectedId === undefined ? 'secondary' : 'ghost'} className='justify-start' onClick={() => onSelect(undefined)}>
          {allLabel}
        </Button>
        {treeViewportClassName ? (
          <ScrollArea data-testid='sortable-tree-scroll-area' className={treeViewportClassName}>
            <div className='pr-3'>{treeContent}</div>
          </ScrollArea>
        ) : treeContent}
      </CardContent>
    </Card>
  )
}

function SortableTreeRow({ node, selected, draggingDisabled, dragLabel, hasChildren, collapsed, collapseLabel, expandLabel, onToggle, onSelect }: { node: FlatTreeNode; selected: boolean; draggingDisabled: boolean; dragLabel: string; hasChildren: boolean; collapsed: boolean; collapseLabel: string; expandLabel: string; onToggle: () => void; onSelect: () => void }) {
  const { attributes, listeners, setNodeRef, transform, transition, isDragging } = useSortable({ id: node.id, disabled: draggingDisabled })
  return (
    <div ref={setNodeRef} role='treeitem' aria-selected={selected} aria-expanded={hasChildren ? !collapsed : undefined} className={cn('flex items-center rounded-md', selected && 'bg-muted', isDragging && 'opacity-50')} style={{ transform: CSS.Transform.toString(transform), transition, paddingInlineStart: node.depth * 16 }}>
      <Button type='button' variant='ghost' size='icon-xs' disabled={draggingDisabled} aria-label={dragLabel} {...attributes} {...listeners}>
        <GripVertical />
      </Button>
      {hasChildren ? (
        <Button type='button' variant='ghost' size='icon-xs' aria-label={collapsed ? expandLabel : collapseLabel} onClick={onToggle}>
          {collapsed ? <ChevronRight /> : <ChevronDown />}
        </Button>
      ) : <span className='size-6 shrink-0' aria-hidden='true' />}
      <Button type='button' variant='ghost' className='min-w-0 flex-1 justify-start' onClick={onSelect}>
        {node.icon}
        <span className='truncate'>{node.label}</span>
      </Button>
    </div>
  )
}
