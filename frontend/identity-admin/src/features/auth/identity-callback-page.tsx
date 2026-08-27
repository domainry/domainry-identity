import { useEffect, useRef, useState } from 'react'
import { useNavigate } from '@tanstack/react-router'
import { AlertCircle, ShieldCheck } from 'lucide-react'
import { Button, Card, CardContent, Spinner } from '@domainry/ui'
import { useAuth } from '@/lib/auth'
import { useI18n } from '@/lib/i18n'

export function IdentityCallbackPage() {
  const { completeFederatedLoginFromLocation } = useAuth()
  const { t } = useI18n()
  const navigate = useNavigate()
  const started = useRef(false)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    if (started.current) return
    started.current = true
    void completeFederatedLoginFromLocation(window.location.href)
      .then(() => navigate({ to: '/admin/login', replace: true }))
      .catch(() => setFailed(true))
  }, [completeFederatedLoginFromLocation, navigate])

  return (
    <main className='flex min-h-svh items-center justify-center bg-muted/40 px-5'>
      <Card className='w-full max-w-sm'>
        <CardContent className='flex flex-col items-center gap-4 p-8 text-center'>
          {failed ? <AlertCircle className='size-9 text-destructive' /> : <ShieldCheck className='size-9 text-primary' />}
          <div>
            <h1 className='font-display text-xl font-extrabold'>
              {failed ? t('login.callbackFailed') : t('login.callbackTitle')}
            </h1>
            <p className='mt-2 text-sm text-muted-foreground'>
              {failed ? t('login.callbackFailedDescription') : t('login.callbackDescription')}
            </p>
          </div>
          {failed ? (
            <Button type='button' variant='outline' onClick={() => void navigate({ to: '/admin/login', replace: true })}>
              {t('login.backToLogin')}
            </Button>
          ) : <Spinner className='size-5' />}
        </CardContent>
      </Card>
    </main>
  )
}
