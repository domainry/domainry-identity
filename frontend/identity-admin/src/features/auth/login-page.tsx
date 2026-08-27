import { useEffect, useMemo, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { Controller, useForm } from 'react-hook-form'
import { ArrowRight, Building2, Eye, EyeOff, KeyRound, ShieldCheck, Smartphone, User } from 'lucide-react'
import { toast } from 'sonner'
import { z } from 'zod'
import {
  Button,
  Card,
  CardContent,
  Checkbox,
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
  Label,
  Separator,
  Spinner,
} from '@domainry/ui'
import type { IdentityProvider } from '@domainry/identity-client'
import { PRODUCT_BRAND } from '@/config/product-brand'
import { ProductBrandMark } from '@/components/product-brand-mark'
import { useAuth } from '@/lib/auth'
import { useI18n } from '@/lib/i18n'
import { runtimeApiError } from '@/lib/runtime-api'

export function LoginPage() {
  const { t } = useI18n()
  const { providers: loadProviders, login, beginFederatedLogin, beginOTP, verifyOTP } = useAuth()
  const [showPassword, setShowPassword] = useState(false)
  const [loginProviders, setLoginProviders] = useState<IdentityProvider[]>([])
  const [providerLoading, setProviderLoading] = useState(true)
  const [providerPending, setProviderPending] = useState('')
  const [otpProvider, setOTPProvider] = useState<IdentityProvider | null>(null)
  const [otpState, setOTPState] = useState('')
  const [phone, setPhone] = useState('')
  const [otpCode, setOTPCode] = useState('')

  useEffect(() => {
    let active = true
    void loadProviders()
      .then((items) => {
        if (active) setLoginProviders(items.filter((item) => item.enabled))
      })
      .catch(() => undefined)
      .finally(() => {
        if (active) setProviderLoading(false)
      })
    return () => { active = false }
  }, [loadProviders])

  const otpProviders = loginProviders.filter((provider) => (
    provider.type === 'otp' || provider.type === 'sms' || provider.channels?.includes('sms')
  ))
  const federatedProviders = loginProviders.filter((provider) => (
    provider.type !== 'password' && !otpProviders.some((otp) => otp.key === provider.key)
  ))
  const schema = useMemo(
    () =>
      z.object({
        username: z.string().trim().min(1, t('login.validation.usernameRequired')),
        password: z.string().min(1, t('login.validation.passwordRequired')),
        remember: z.boolean(),
      }),
    [t]
  )
  type LoginFormValues = z.input<typeof schema>
  const {
    control,
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<LoginFormValues>({
    resolver: zodResolver(schema),
    defaultValues: { username: '', password: '', remember: true },
    mode: 'onBlur',
  })

  async function submit(values: LoginFormValues) {
    try {
      await login(values.username.trim(), values.password, { remember: values.remember })
      toast.success(t('login.success'))
    } catch (error) {
      const code = runtimeApiError(error)?.code
      const message = code === 'auth.invalid_credentials'
        ? t('login.failed')
        : code === 'auth.account_locked'
          ? t('login.accountLocked')
          : code === 'auth.permission_denied'
            ? t('login.accessMisconfigured')
            : t('login.unavailable')
      setError('root', { message })
    }
  }

  async function startFederated(provider: IdentityProvider) {
    setProviderPending(provider.key)
    try {
      await beginFederatedLogin(provider.key)
    } catch {
      setError('root', { message: t('login.providerUnavailable') })
      setProviderPending('')
    }
  }

  async function sendOTP() {
    if (!otpProvider || !phone.trim()) return
    setProviderPending(otpProvider.key)
    try {
      const challenge = await beginOTP(otpProvider.key, phone)
      setOTPState(challenge.state)
    } catch {
      setError('root', { message: t('login.providerUnavailable') })
    } finally {
      setProviderPending('')
    }
  }

  async function submitOTP() {
    if (!otpProvider || !otpState || !otpCode.trim()) return
    setProviderPending(otpProvider.key)
    try {
      await verifyOTP(otpProvider.key, otpState, otpCode)
      toast.success(t('login.success'))
    } catch {
      setError('root', { message: t('login.otpInvalid') })
    } finally {
      setProviderPending('')
    }
  }

  return (
    <div className='min-h-svh bg-[oklch(0.976_0.006_258)] text-foreground dark:bg-background'>
      <div className='grid min-h-svh lg:grid-cols-[minmax(0,1.05fr)_minmax(440px,0.95fr)]'>
        <section className='relative hidden overflow-hidden border-r bg-[linear-gradient(135deg,oklch(0.985_0.004_258),oklch(0.948_0.020_262))] lg:block'>
          <div className='absolute inset-0 bg-[linear-gradient(to_right,oklch(0.70_0.018_258/0.14)_1px,transparent_1px),linear-gradient(to_bottom,oklch(0.70_0.018_258/0.14)_1px,transparent_1px)] bg-[size:44px_44px]' />
          <div className='relative flex min-h-svh flex-col justify-between p-10 xl:p-12'>
            <div className='flex items-center gap-3'>
              <span
                className='flex size-10 items-center justify-center rounded-lg text-white shadow-sm'
                style={{ background: 'var(--gradient-brand)' }}
              >
                <ProductBrandMark className='size-5' />
              </span>
              <div>
                <p className='font-display text-lg font-extrabold leading-none tracking-tight'>
                  {PRODUCT_BRAND.consoleTitle}
                </p>
                <p className='mt-1 text-xs text-muted-foreground'>{t('login.brandKicker')}</p>
              </div>
            </div>

            <div className='max-w-xl'>
              <p className='mb-4 inline-flex items-center gap-2 rounded-full border bg-background/75 px-3 py-1 text-xs font-medium text-muted-foreground shadow-xs backdrop-blur'>
                <ShieldCheck className='size-3.5 text-primary' />
                {t('login.secureBadge')}
              </p>
              <h1 className='font-display text-4xl font-extrabold leading-tight tracking-tight xl:text-5xl'>
                <span className='block'>{t('login.brandTitleLine1')}</span>
                <span className='block'>{t('login.brandTitleLine2')}</span>
              </h1>
              <p className='mt-4 max-w-lg text-sm leading-relaxed text-muted-foreground'>
                {t('login.brandDesc')}
              </p>

              <div className='mt-10 max-w-lg space-y-2'>
                {[t('login.point.rbac'), t('login.point.audit')].map((item) => (
                  <div
                    key={item}
                    className='flex items-center justify-between rounded-md border bg-background/70 px-3 py-3 text-sm shadow-xs backdrop-blur'
                  >
                    <span className='inline-flex items-center gap-2 text-muted-foreground'>
                      <span className='size-1.5 rounded-full bg-primary' />
                      {item}
                    </span>
                    <ArrowRight className='size-4 text-muted-foreground' />
                  </div>
                ))}
              </div>
            </div>

            <p className='text-xs text-muted-foreground'>{PRODUCT_BRAND.copyrightNotice}</p>
          </div>
        </section>

        <main className='flex min-h-svh items-center justify-center px-5 py-8 sm:px-8'>
          <Card className='w-full max-w-[420px] rounded-lg border bg-card/95 shadow-lg'>
            <CardContent className='p-6 sm:p-8'>
              <div className='mb-7'>
                <div className='mb-5 flex items-center gap-3 lg:hidden'>
                  <span
                    className='flex size-9 items-center justify-center rounded-lg text-white shadow-sm'
                    style={{ background: 'var(--gradient-brand)' }}
                  >
                    <ProductBrandMark className='size-4' />
                  </span>
                  <div>
                    <p className='font-display text-base font-extrabold leading-none tracking-tight'>
                      {PRODUCT_BRAND.consoleTitle}
                    </p>
                    <p className='mt-1 text-xs text-muted-foreground'>{t('login.brandKicker')}</p>
                  </div>
                </div>
                <p className='mb-2 text-xs font-medium uppercase tracking-wide text-primary'>
                  {t('login.secureBadge')}
                </p>
                <h2 className='font-display text-2xl font-extrabold tracking-tight'>
                  {t('login.title')}
                </h2>
                <p className='mt-2 text-sm leading-relaxed text-muted-foreground'>
                  {t('login.subtitle')}
                </p>
              </div>
              <form onSubmit={handleSubmit(submit)} noValidate>
                <FieldGroup className='gap-4'>
                  <Field data-invalid={Boolean(errors.username)}>
                    <FieldLabel htmlFor='login-username'>{t('login.username')}</FieldLabel>
                    <InputGroup>
                      <InputGroupInput
                        id='login-username'
                        autoComplete='username'
                        placeholder={t('login.usernamePlaceholder')}
                        aria-invalid={Boolean(errors.username)}
                        {...register('username')}
                      />
                      <InputGroupAddon className='w-10 flex-none px-3!' align='inline-start' data-testid='login-username-addon'>
                        <User />
                      </InputGroupAddon>
                    </InputGroup>
                    <FieldError errors={[errors.username]} />
                  </Field>
                  <Field data-invalid={Boolean(errors.password)}>
                    <FieldLabel htmlFor='login-password'>{t('login.password')}</FieldLabel>
                    <InputGroup>
                      <InputGroupInput
                        id='login-password'
                        type={showPassword ? 'text' : 'password'}
                        autoComplete='current-password'
                        placeholder={t('login.passwordPlaceholder')}
                        aria-invalid={Boolean(errors.password)}
                        {...register('password')}
                      />
                      <InputGroupAddon className='w-10 flex-none px-3!' align='inline-start' data-testid='login-password-addon'>
                        <KeyRound />
                      </InputGroupAddon>
                      <InputGroupAddon className='w-10 flex-none px-2! has-[>button]:mr-0!' align='inline-end' data-testid='login-password-end-addon'>
                        <InputGroupButton
                          size='icon-xs'
                          aria-label={showPassword ? t('login.hidePassword') : t('login.showPassword')}
                          onClick={() => setShowPassword((v) => !v)}
                        >
                          {showPassword ? <EyeOff /> : <Eye />}
                        </InputGroupButton>
                      </InputGroupAddon>
                    </InputGroup>
                    <FieldError errors={[errors.password]} />
                  </Field>
                  <div className='flex items-center justify-between'>
                    <Label className='flex items-center gap-2 text-sm font-normal'>
                      <Controller
                        control={control}
                        name='remember'
                        render={({ field }) => (
                          <Checkbox
                            checked={field.value}
                            onCheckedChange={(value) => field.onChange(value === true)}
                          />
                        )}
                      />
                      {t('login.remember')}
                    </Label>
                    <Button variant='link' size='sm' type='button' className='px-0'>
                      {t('login.forgot')}
                    </Button>
                  </div>
                  <FieldError errors={[errors.root]} />
                  <Button
                    type='submit'
                    className='mt-1 w-full gap-2'
                    disabled={isSubmitting}
                    style={{ background: 'var(--gradient-brand)', boxShadow: 'var(--shadow-glow-brand)' }}
                  >
                    {isSubmitting ? <Spinner className='size-4' /> : null}
                    {isSubmitting ? t('login.submitting') : t('login.submit')}
                    {!isSubmitting ? <ArrowRight className='size-4' /> : null}
                  </Button>
                </FieldGroup>
              </form>

              {providerLoading ? (
                <div className='mt-5 flex items-center justify-center gap-2 text-xs text-muted-foreground'>
                  <Spinner className='size-3.5' />
                  {t('login.loadingProviders')}
                </div>
              ) : null}

              {federatedProviders.length || otpProviders.length ? (
                <div className='mt-6 space-y-3'>
                  <div className='flex items-center gap-3'>
                    <Separator className='flex-1' />
                    <span className='text-xs text-muted-foreground'>{t('login.otherMethods')}</span>
                    <Separator className='flex-1' />
                  </div>
                  {federatedProviders.map((provider) => (
                    <Button
                      key={provider.key}
                      type='button'
                      variant='outline'
                      className='w-full justify-start gap-3'
                      disabled={Boolean(providerPending)}
                      onClick={() => void startFederated(provider)}
                    >
                      {providerPending === provider.key ? <Spinner className='size-4' /> : <Building2 className='size-4' />}
                      {provider.label || provider.key}
                    </Button>
                  ))}
                  {otpProviders.map((provider) => (
                    <Button
                      key={provider.key}
                      type='button'
                      variant='outline'
                      className='w-full justify-start gap-3'
                      disabled={Boolean(providerPending)}
                      onClick={() => {
                        setOTPProvider(provider)
                        setOTPState('')
                        setOTPCode('')
                      }}
                    >
                      <Smartphone className='size-4' />
                      {provider.label || t('login.otp')}
                    </Button>
                  ))}
                </div>
              ) : null}

              {otpProvider ? (
                <div className='mt-4 space-y-3 rounded-md border bg-muted/30 p-3'>
                  <p className='text-sm font-medium'>{otpProvider.label || t('login.otp')}</p>
                  {!otpState ? (
                    <>
                      <InputGroup>
                        <InputGroupInput value={phone} onChange={(event) => setPhone(event.target.value)} placeholder={t('login.phonePlaceholder')} autoComplete='tel' />
                        <InputGroupAddon align='inline-start'><Smartphone /></InputGroupAddon>
                      </InputGroup>
                      <Button type='button' className='w-full' disabled={!phone.trim() || Boolean(providerPending)} onClick={() => void sendOTP()}>
                        {providerPending ? <Spinner className='size-4' /> : null}
                        {t('login.sendCode')}
                      </Button>
                    </>
                  ) : (
                    <>
                      <InputGroup>
                        <InputGroupInput value={otpCode} onChange={(event) => setOTPCode(event.target.value)} placeholder={t('login.codePlaceholder')} autoComplete='one-time-code' inputMode='numeric' />
                        <InputGroupAddon align='inline-start'><KeyRound /></InputGroupAddon>
                      </InputGroup>
                      <Button type='button' className='w-full' disabled={!otpCode.trim() || Boolean(providerPending)} onClick={() => void submitOTP()}>
                        {providerPending ? <Spinner className='size-4' /> : null}
                        {t('login.verifyCode')}
                      </Button>
                    </>
                  )}
                </div>
              ) : null}
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  )
}
