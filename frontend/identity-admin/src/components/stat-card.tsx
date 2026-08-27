import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

type StatDeltaTone = 'up' | 'down' | 'neutral'

interface StatCardProps {
  /** Short uppercase metric label, e.g. "本月新增商机". */
  label: ReactNode
  /** Headline value; rendered with display font + tabular numerals. */
  value: ReactNode
  /** Optional delta line, e.g. "+12.4% 环比". */
  delta?: ReactNode
  /** Colors the delta: up=complete, down=risk, neutral=muted. */
  deltaTone?: StatDeltaTone
  className?: string
}

const deltaToneClass: Record<StatDeltaTone, string> = {
  up: 'text-complete',
  down: 'text-risk',
  neutral: 'text-muted-foreground',
}

/**
 * KPI stat card: meta label, display-font
 * value with tabular numerals, optional tone-colored delta.
 */
export function StatCard({
  label,
  value,
  delta,
  deltaTone = 'neutral',
  className,
}: StatCardProps) {
  return (
    <div
      data-slot='stat-card'
      className={cn(
        'rounded-lg border bg-card px-3.5 py-3 text-card-foreground shadow-(--card-shadow)',
        className
      )}
    >
      <div className='mb-1.5 text-(length:--font-size-meta) font-medium tracking-[0.07em] uppercase text-muted-foreground'>
        {label}
      </div>
      <div className='num font-display text-2xl leading-tight font-extrabold tracking-tight'>
        {value}
      </div>
      {delta != null ? (
        <div className={cn('mt-1 text-xs font-bold', deltaToneClass[deltaTone])}>
          {delta}
        </div>
      ) : null}
    </div>
  )
}

/** Responsive grid wrapper for a row of StatCards. */
export function StatGrid({
  className,
  children,
}: {
  className?: string
  children: ReactNode
}) {
  return (
    <div
      data-slot='stat-grid'
      className={cn('grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3', className)}
    >
      {children}
    </div>
  )
}
