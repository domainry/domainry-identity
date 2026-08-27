import { Component, type ErrorInfo, type ReactNode } from 'react'
import { CircleAlert, RefreshCw } from 'lucide-react'
import { Alert, AlertDescription, AlertTitle, Button } from '@domainry/ui'
import { useI18n } from '@/lib/i18n'

interface BoundaryProps {
  children: ReactNode
  resetKey: string
  fallback: (error: Error, reset: () => void) => ReactNode
}

interface BoundaryState {
  error: Error | null
}

class ContentErrorBoundary extends Component<BoundaryProps, BoundaryState> {
  state: BoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): BoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('Page content render failed', error, info.componentStack)
  }

  componentDidUpdate(previous: BoundaryProps) {
    if (previous.resetKey !== this.props.resetKey && this.state.error) {
      this.setState({ error: null })
    }
  }

  private reset = () => this.setState({ error: null })

  render() {
    return this.state.error
      ? this.props.fallback(this.state.error, this.reset)
      : this.props.children
  }
}

export function PageErrorBoundary({ children, resetKey }: { children: ReactNode; resetKey: string }) {
  const { t } = useI18n()
  return (
    <ContentErrorBoundary
      resetKey={resetKey}
      fallback={(error, reset) => (
        <main className='p-4 md:p-6'>
          <Alert variant='destructive'>
            <CircleAlert />
            <AlertTitle>{t('errorBoundary.title')}</AlertTitle>
            <AlertDescription>
              <p>{t('errorBoundary.description')}</p>
              <p className='mt-1 font-mono text-xs'>{error.message}</p>
              <div className='mt-4 flex flex-wrap gap-2'>
                <Button variant='outline' size='sm' onClick={reset}>
                  <RefreshCw data-icon='inline-start' />
                  {t('errorBoundary.retry')}
                </Button>
                <Button size='sm' onClick={() => window.location.reload()}>
                  {t('errorBoundary.reload')}
                </Button>
              </div>
            </AlertDescription>
          </Alert>
        </main>
      )}
    >
      {children}
    </ContentErrorBoundary>
  )
}
