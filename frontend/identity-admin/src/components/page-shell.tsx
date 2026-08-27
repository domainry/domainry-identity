import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export function PageShell({
  title,
  description,
  actions,
  mode = 'fill',
  children,
}: {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  mode?: 'fill' | 'centered'
  children: ReactNode
}) {
  return (
    <main
      data-page-shell-mode={mode}
      className={cn(
        'flex min-w-0 flex-1 flex-col gap-4 p-4 md:p-5',
        mode === 'centered' && 'mx-auto w-full max-w-5xl'
      )}
    >
      <div className='flex min-w-0 flex-col gap-3 lg:flex-row lg:items-start lg:justify-between'>
        <div className='min-w-0'>
          <h1 className='break-words text-xl font-semibold tracking-normal'>{title}</h1>
          {description ? (
            <p className='mt-1 max-w-3xl break-words text-sm text-muted-foreground'>{description}</p>
          ) : null}
        </div>
        {actions ? <div className='flex min-w-0 flex-wrap items-center gap-2 lg:shrink-0'>{actions}</div> : null}
      </div>
      {children}
    </main>
  )
}
