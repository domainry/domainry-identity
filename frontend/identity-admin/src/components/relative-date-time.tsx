import { useEffect, useMemo, useState } from 'react'
import { Tooltip, TooltipContent, TooltipTrigger } from '@domainry/ui'
import { useI18n, type Locale } from '@/lib/i18n'

type RelativeUnit = Intl.RelativeTimeFormatUnit

const UNITS: Array<{ unit: RelativeUnit; milliseconds: number }> = [
  { unit: 'year', milliseconds: 365 * 24 * 60 * 60 * 1000 },
  { unit: 'month', milliseconds: 30 * 24 * 60 * 60 * 1000 },
  { unit: 'week', milliseconds: 7 * 24 * 60 * 60 * 1000 },
  { unit: 'day', milliseconds: 24 * 60 * 60 * 1000 },
  { unit: 'hour', milliseconds: 60 * 60 * 1000 },
  { unit: 'minute', milliseconds: 60 * 1000 },
  { unit: 'second', milliseconds: 1000 },
]

function relativeValue(date: Date, now: number, locale: string) {
  const difference = date.getTime() - now
  const selected = UNITS.find(({ milliseconds }) => Math.abs(difference) >= milliseconds) ?? UNITS.at(-1)!
  return new Intl.RelativeTimeFormat(locale, { numeric: 'auto' }).format(
    Math.round(difference / selected.milliseconds),
    selected.unit
  )
}

export function formatDateTime(value: string | Date, locale: Locale) {
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) return '—'
  return new Intl.DateTimeFormat(locale === 'en' ? 'en-US' : 'zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'medium',
  }).format(date)
}

export function RelativeDateTime({ value }: { value?: string | null }) {
  const { locale, t } = useI18n()
  const [now, setNow] = useState(Date.now)
  const date = useMemo(() => {
    if (!value || value === '—') return null
    const parsed = new Date(value)
    return Number.isNaN(parsed.getTime()) ? null : parsed
  }, [value])

  useEffect(() => {
    if (!date) return
    const timer = window.setInterval(() => setNow(Date.now()), 60_000)
    return () => window.clearInterval(timer)
  }, [date])

  if (!date) return <span className='text-muted-foreground'>{t('time.never')}</span>

  const intlLocale = locale === 'en' ? 'en-US' : 'zh-CN'
  const full = formatDateTime(date, locale)

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <time dateTime={date.toISOString()} className='cursor-help text-muted-foreground tabular-nums'>
          {relativeValue(date, now, intlLocale)}
        </time>
      </TooltipTrigger>
      <TooltipContent>{full}</TooltipContent>
    </Tooltip>
  )
}
