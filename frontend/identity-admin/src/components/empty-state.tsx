import type { ComponentType, ReactNode } from 'react'
import { SearchX } from 'lucide-react'
import { cn } from '@/lib/utils'

/**
 * Shared empty state for list/table pages: shows an icon, a title, an
 * optional hint and an optional action (e.g. "clear filters").
 */
export function EmptyState({
  icon: Icon = SearchX,
  title,
  description,
  action,
  className,
}: {
  icon?: ComponentType<{ className?: string }>
  title: ReactNode
  description?: ReactNode
  action?: ReactNode
  className?: string
}) {
  return (
    <div
      data-slot='empty-state'
      className={cn(
        'flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed px-6 py-10 text-center',
        className
      )}
    >
      <span className='flex size-10 items-center justify-center rounded-full bg-muted text-muted-foreground'>
        <Icon className='size-5' />
      </span>
      <p className='text-sm font-medium'>{title}</p>
      {description ? (
        <p className='max-w-sm text-xs text-muted-foreground'>{description}</p>
      ) : null}
      {action ? <div className='mt-1'>{action}</div> : null}
    </div>
  )
}
