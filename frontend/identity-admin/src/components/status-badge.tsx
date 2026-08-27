import type { ReactNode } from 'react'
import type { VariantProps } from 'class-variance-authority'
import { Badge, badgeVariants } from '@domainry/ui'
import { cn } from '@/lib/utils'

type BadgeVariant = NonNullable<VariantProps<typeof badgeVariants>['variant']>

const STATUS_TONES: Record<string, BadgeVariant> = {
  active: 'success',
  enabled: 'success',
  enable: 'success',
  success: 'success',
  successful: 'success',
  succeeded: 'success',
  complete: 'complete',
  completed: 'complete',
  done: 'complete',
  closed: 'complete',
  resolved: 'complete',
  warning: 'warning',
  warn: 'warning',
  at_risk: 'risk',
  risk: 'risk',
  risky: 'risk',
  failed: 'risk',
  failure: 'risk',
  error: 'risk',
  rejected: 'risk',
  overdue: 'overdue',
  expired: 'overdue',
  late: 'overdue',
  pending: 'pending',
  queued: 'pending',
  running: 'pending',
  processing: 'pending',
  in_progress: 'pending',
  approving: 'pending',
  approval_pending: 'pending',
  disabled: 'disabled',
  disable: 'disabled',
  inactive: 'disabled',
  locked: 'disabled',
  paused: 'disabled',
  draft: 'draft',
  new: 'draft',
}

export function statusToneForValue(value: unknown): BadgeVariant {
  if (value === true) return 'success'
  if (value === false) return 'disabled'
  const key = String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_')
  return STATUS_TONES[key] ?? 'outline'
}

/**
 * Soft-tone surfaces use lighter fill +
 * tinted foreground so the badge reads quieter than the table body text.
 */
const SOFT_TONE_CLASS: Partial<Record<BadgeVariant, string>> = {
  success: 'bg-(--success-soft) text-(--success-soft-foreground)',
  complete: 'bg-(--complete-soft) text-(--complete-soft-foreground)',
  warning: 'bg-(--warning-soft) text-(--warning-soft-foreground)',
  risk: 'bg-(--risk-soft) text-(--risk-soft-foreground)',
  overdue: 'bg-(--overdue-soft) text-(--overdue-soft-foreground)',
  pending: 'bg-(--pending-soft) text-(--pending-soft-foreground)',
  disabled: 'bg-(--disabled-soft) text-(--disabled-soft-foreground)',
  draft: 'bg-(--draft-soft) text-(--draft-soft-foreground)',
}

export function StatusBadge({
  value,
  children,
}: {
  value: unknown
  children: ReactNode
}) {
  const tone = statusToneForValue(value)
  const soft = SOFT_TONE_CLASS[tone]
  return (
    <Badge
      variant={soft ? 'outline' : tone}
      dot
      className={cn('px-2 text-[11px] font-medium', soft && cn('border-transparent', soft))}
    >
      {children}
    </Badge>
  )
}
