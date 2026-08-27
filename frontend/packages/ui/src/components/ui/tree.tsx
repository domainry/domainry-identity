import * as React from 'react'
import { ChevronRight, Check, ChevronsUpDown } from 'lucide-react'
import { cn } from '../../lib/utils'
import { Button } from './button'
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from './command'
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from './popover'

/* ------------------------------------------------------------------ */
/* Tree data model                                                     */
/* ------------------------------------------------------------------ */

export type TreeNode = {
  id: string
  label: string
  icon?: React.ReactNode
  children?: TreeNode[]
  disabled?: boolean
}

/* ------------------------------------------------------------------ */
/* TreeView — collapsible hierarchical list                            */
/* ------------------------------------------------------------------ */

type TreeViewProps = {
  data: TreeNode[]
  /** Node ids expanded by default. */
  defaultExpanded?: string[]
  selectedId?: string
  onSelect?: (node: TreeNode) => void
  className?: string
}

function TreeView({
  data,
  defaultExpanded = [],
  selectedId,
  onSelect,
  className,
}: TreeViewProps) {
  const [expanded, setExpanded] = React.useState<Set<string>>(
    () => new Set(defaultExpanded)
  )

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  return (
    <div
      role='tree'
      data-slot='tree-view'
      className={cn('flex flex-col gap-0.5 text-sm', className)}
    >
      {data.map((node) => (
        <TreeViewItem
          key={node.id}
          node={node}
          depth={0}
          expanded={expanded}
          onToggle={toggle}
          selectedId={selectedId}
          onSelect={onSelect}
        />
      ))}
    </div>
  )
}

function TreeViewItem({
  node,
  depth,
  expanded,
  onToggle,
  selectedId,
  onSelect,
}: {
  node: TreeNode
  depth: number
  expanded: Set<string>
  onToggle: (id: string) => void
  selectedId?: string
  onSelect?: (node: TreeNode) => void
}) {
  const hasChildren = (node.children?.length ?? 0) > 0
  const isOpen = expanded.has(node.id)
  const isSelected = selectedId === node.id

  return (
    <div role='none'>
      <button
        type='button'
        role='treeitem'
        aria-expanded={hasChildren ? isOpen : undefined}
        aria-selected={isSelected}
        disabled={node.disabled}
        style={{ paddingInlineStart: `${depth * 16 + 4}px` }}
        className={cn(
          'flex w-full items-center gap-1.5 rounded-md py-1.5 pe-2 text-start outline-hidden transition-colors',
          'hover:bg-muted focus-visible:ring-ring/50 focus-visible:ring-[3px]',
          isSelected && 'bg-muted font-medium text-primary',
          node.disabled && 'pointer-events-none opacity-50'
        )}
        onClick={() => {
          if (hasChildren) onToggle(node.id)
          onSelect?.(node)
        }}
      >
        <ChevronRight
          className={cn(
            'size-4 shrink-0 text-muted-foreground transition-transform',
            isOpen && 'rotate-90',
            !hasChildren && 'invisible'
          )}
        />
        {node.icon != null && (
          <span className='inline-flex shrink-0 items-center text-muted-foreground [&_svg]:size-4'>
            {node.icon}
          </span>
        )}
        <span className='truncate'>{node.label}</span>
      </button>
      {hasChildren && isOpen && (
        <div role='group' className='flex flex-col gap-0.5'>
          {node.children!.map((child) => (
            <TreeViewItem
              key={child.id}
              node={child}
              depth={depth + 1}
              expanded={expanded}
              onToggle={onToggle}
              selectedId={selectedId}
              onSelect={onSelect}
            />
          ))}
        </div>
      )}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* TreeSelect — popover + searchable tree list                         */
/* ------------------------------------------------------------------ */

type FlatNode = { node: TreeNode; depth: number; path: string }

function flattenTree(
  nodes: TreeNode[],
  depth = 0,
  parentPath = ''
): FlatNode[] {
  return nodes.flatMap((node) => {
    const path = parentPath ? `${parentPath} / ${node.label}` : node.label
    return [
      { node, depth, path },
      ...flattenTree(node.children ?? [], depth + 1, path),
    ]
  })
}

type TreeSelectProps = {
  data: TreeNode[]
  value?: string
  onValueChange?: (id: string) => void
  placeholder?: string
  searchPlaceholder?: string
  emptyText?: string
  /** Only leaf nodes are selectable when true (default). */
  leafOnly?: boolean
  className?: string
}

function TreeSelect({
  data,
  value,
  onValueChange,
  placeholder = 'Select…',
  searchPlaceholder = 'Search…',
  emptyText = 'No results.',
  leafOnly = true,
  className,
}: TreeSelectProps) {
  const [open, setOpen] = React.useState(false)
  const flat = React.useMemo(() => flattenTree(data), [data])
  const selected = flat.find((item) => item.node.id === value)

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant='outline'
          role='combobox'
          aria-expanded={open}
          className={cn(
            'w-60 justify-between font-normal',
            !selected && 'text-muted-foreground',
            className
          )}
        >
          <span className='truncate'>
            {selected ? selected.path : placeholder}
          </span>
          <ChevronsUpDown className='size-4 shrink-0 opacity-50' />
        </Button>
      </PopoverTrigger>
      <PopoverContent className='w-(--radix-popover-trigger-width) min-w-60 p-0'>
        <Command
          filter={(itemValue, search) =>
            itemValue.toLowerCase().includes(search.toLowerCase()) ? 1 : 0
          }
        >
          <CommandInput placeholder={searchPlaceholder} />
          <CommandList>
            <CommandEmpty>{emptyText}</CommandEmpty>
            <CommandGroup>
              {flat.map(({ node, depth, path }) => {
                const isBranch = (node.children?.length ?? 0) > 0
                const selectable = !node.disabled && (!leafOnly || !isBranch)
                return (
                  <CommandItem
                    key={node.id}
                    value={path}
                    disabled={!selectable}
                    onSelect={() => {
                      onValueChange?.(node.id)
                      setOpen(false)
                    }}
                    style={{ paddingInlineStart: `${depth * 14 + 8}px` }}
                  >
                    <Check
                      className={cn(
                        'size-4',
                        value === node.id ? 'opacity-100' : 'opacity-0'
                      )}
                    />
                    <span className={cn(isBranch && 'font-medium')}>
                      {node.label}
                    </span>
                  </CommandItem>
                )
              })}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

export { TreeView, TreeSelect }
