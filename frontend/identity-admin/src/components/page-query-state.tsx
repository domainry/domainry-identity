import type { ReactNode } from 'react'
import { Alert, AlertDescription, AlertTitle, Button, Skeleton } from '@domainry/ui'
import { PageShell } from '@/components/page-shell'
import { useI18n } from '@/lib/i18n'

export function PageQueryState({
  title,
  description,
  error,
  onRetry,
}: {
  title: ReactNode
  description?: ReactNode
  error?: Error | null
  onRetry?: () => void
}) {
  const { t } = useI18n()
  return (
    <PageShell title={title} description={description}>
      {error ? (
        <Alert variant='destructive'>
          <AlertTitle>{t('dataTable.errorTitle')}</AlertTitle>
          <AlertDescription className='flex flex-wrap items-center justify-between gap-2'>
            <span>{error.message || t('dataTable.errorDescription')}</span>
            {onRetry ? <Button size='sm' variant='outline' onClick={onRetry}>{t('common.retry')}</Button> : null}
          </AlertDescription>
        </Alert>
      ) : <Skeleton className='h-72 w-full rounded-lg' />}
    </PageShell>
  )
}
