import { useMemo, useState } from 'react'
import { zodResolver } from '@hookform/resolvers/zod'
import { useForm, type FieldError as FormFieldError, type UseFormRegister } from 'react-hook-form'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
  Spinner,
} from '@domainry/ui'
import {
  ArrowRight,
  Eye,
  EyeOff,
  KeyRound,
  LogOut,
  ShieldCheck,
} from 'lucide-react'
import { z } from 'zod'
import { PRODUCT_BRAND } from '@/config/product-brand'
import { ProductBrandMark } from '@/components/product-brand-mark'
import { useAuth } from '@/lib/auth'
import { runtimeApiError } from '@/lib/runtime-api'
import { useI18n } from '@/lib/i18n'

type PasswordFieldName = 'currentPassword' | 'newPassword' | 'confirmPassword'
type ChangePasswordFormValues = Record<PasswordFieldName, string>

export function ChangePasswordPage({ onSuccess }: { onSuccess: () => void }) {
  const { t } = useI18n()
  const { changePassword, logout } = useAuth()
  const [visible, setVisible] = useState<Record<PasswordFieldName, boolean>>({
    currentPassword: false,
    newPassword: false,
    confirmPassword: false,
  })
  const schema = useMemo(
    () =>
      z
        .object({
          currentPassword: z.string().min(1, t('changePassword.validation.currentRequired')),
          newPassword: z.string().min(1, t('changePassword.validation.newRequired')),
          confirmPassword: z.string().min(1, t('changePassword.validation.confirmRequired')),
        })
        .refine((values) => values.newPassword !== values.currentPassword, {
          path: ['newPassword'],
          message: t('changePassword.validation.mustDiffer'),
        })
        .refine((values) => values.newPassword === values.confirmPassword, {
          path: ['confirmPassword'],
          message: t('changePassword.validation.mismatch'),
        }),
    [t],
  )
  type FormValues = z.input<typeof schema>
  const {
    register,
    handleSubmit,
    setError,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: { currentPassword: '', newPassword: '', confirmPassword: '' },
    mode: 'onBlur',
  })

  async function submit(values: FormValues) {
    try {
      const next = await changePassword(values.currentPassword, values.newPassword)
      if (next.mustChangePassword) {
        setError('root', { message: t('changePassword.stillRequired') })
        return
      }
      onSuccess()
    } catch (error) {
      const runtime = runtimeApiError(error)
      const knownMessage = runtime?.code
        ? t(`changePassword.error.${runtime.code}` as never)
        : ''
      const facts = [
        knownMessage || (error instanceof Error ? error.message : t('changePassword.failed')),
        runtime?.code,
        runtime?.payload.detail,
        runtime?.requestId ? `request_id=${runtime.requestId}` : '',
      ].filter(Boolean)
      setError('root', { message: [...new Set(facts)].join(' · ') })
    }
  }

  function toggle(field: PasswordFieldName) {
    setVisible((current) => ({ ...current, [field]: !current[field] }))
  }

  return (
    <div className='min-h-svh bg-[oklch(0.976_0.006_258)] text-foreground dark:bg-background'>
      <div className='grid min-h-svh lg:grid-cols-[minmax(0,1.05fr)_minmax(440px,0.95fr)]'>
        <section className='relative hidden overflow-hidden border-r bg-[linear-gradient(135deg,oklch(0.985_0.004_258),oklch(0.948_0.020_262))] lg:block'>
          <div className='absolute inset-0 bg-[linear-gradient(to_right,oklch(0.70_0.018_258/0.14)_1px,transparent_1px),linear-gradient(to_bottom,oklch(0.70_0.018_258/0.14)_1px,transparent_1px)] bg-[size:44px_44px]' />
          <div className='relative flex min-h-svh flex-col justify-between p-10 xl:p-12'>
            <Brand />
            <div className='max-w-xl'>
              <p className='mb-4 inline-flex items-center gap-2 rounded-full border bg-background/75 px-3 py-1 text-xs font-medium text-muted-foreground shadow-xs backdrop-blur'>
                <ShieldCheck className='size-3.5 text-primary' />
                {t('changePassword.badge')}
              </p>
              <h1 className='font-display text-4xl font-extrabold leading-tight tracking-tight xl:text-5xl'>
                {t('changePassword.brandTitle')}
              </h1>
              <p className='mt-4 max-w-lg text-sm leading-relaxed text-muted-foreground'>
                {t('changePassword.brandDescription')}
              </p>
              <div className='mt-8 rounded-lg border bg-background/75 p-4 shadow-xs backdrop-blur'>
                <p className='text-sm font-semibold'>{t('changePassword.flowTitle')}</p>
                <p className='mt-2 text-sm leading-relaxed text-muted-foreground'>
                  {t('changePassword.flowDescription')}
                </p>
              </div>
            </div>
            <p className='text-xs text-muted-foreground'>{PRODUCT_BRAND.copyrightNotice}</p>
          </div>
        </section>

        <main className='flex min-h-svh items-center justify-center px-5 py-8 sm:px-8'>
          <Card className='w-full max-w-[440px] rounded-lg border bg-card/95 shadow-lg'>
            <CardContent className='p-6 sm:p-8'>
              <div className='mb-7'>
                <div className='mb-5 lg:hidden'><Brand /></div>
                <p className='mb-2 text-xs font-medium uppercase tracking-wide text-primary'>
                  {t('changePassword.badge')}
                </p>
                <h2 className='font-display text-2xl font-extrabold tracking-tight'>
                  {t('changePassword.title')}
                </h2>
                <p className='mt-2 text-sm leading-relaxed text-muted-foreground'>
                  {t('changePassword.subtitle')}
                </p>
              </div>

              <Alert className='mb-5'>
                <ShieldCheck />
                <AlertTitle>{t('changePassword.policyTitle')}</AlertTitle>
                <AlertDescription>{t('changePassword.policyDescription')}</AlertDescription>
              </Alert>

              <form onSubmit={handleSubmit(submit)} noValidate>
                <FieldGroup className='gap-4'>
                  <PasswordField
                    name='currentPassword'
                    label={t('changePassword.current')}
                    autoComplete='current-password'
                    visible={visible.currentPassword}
                    error={errors.currentPassword}
                    register={register}
                    onToggle={() => toggle('currentPassword')}
                    showLabel={t('login.showPassword')}
                    hideLabel={t('login.hidePassword')}
                  />
                  <PasswordField
                    name='newPassword'
                    label={t('changePassword.new')}
                    autoComplete='new-password'
                    visible={visible.newPassword}
                    error={errors.newPassword}
                    register={register}
                    onToggle={() => toggle('newPassword')}
                    showLabel={t('login.showPassword')}
                    hideLabel={t('login.hidePassword')}
                  />
                  <PasswordField
                    name='confirmPassword'
                    label={t('changePassword.confirm')}
                    autoComplete='new-password'
                    visible={visible.confirmPassword}
                    error={errors.confirmPassword}
                    register={register}
                    onToggle={() => toggle('confirmPassword')}
                    showLabel={t('login.showPassword')}
                    hideLabel={t('login.hidePassword')}
                  />
                  {errors.root ? (
                    <Alert variant='destructive'>
                      <AlertTitle>{t('changePassword.failedTitle')}</AlertTitle>
                      <AlertDescription>{errors.root.message}</AlertDescription>
                    </Alert>
                  ) : null}
                  <Button
                    type='submit'
                    className='mt-1 w-full gap-2'
                    disabled={isSubmitting}
                    style={{ background: 'var(--gradient-brand)', boxShadow: 'var(--shadow-glow-brand)' }}
                  >
                    {isSubmitting ? <Spinner className='size-4' /> : null}
                    {isSubmitting ? t('changePassword.submitting') : t('changePassword.submit')}
                    {!isSubmitting ? <ArrowRight className='size-4' /> : null}
                  </Button>
                  <Button
                    type='button'
                    variant='ghost'
                    className='w-full gap-2'
                    disabled={isSubmitting}
                    onClick={() => void logout()}
                  >
                    <LogOut className='size-4' />
                    {t('changePassword.logout')}
                  </Button>
                </FieldGroup>
              </form>
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  )
}

function Brand() {
  const { t } = useI18n()
  return (
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
  )
}

function PasswordField({
  name,
  label,
  autoComplete,
  visible,
  error,
  register,
  onToggle,
  showLabel,
  hideLabel,
}: {
  name: PasswordFieldName
  label: string
  autoComplete: string
  visible: boolean
  error?: FormFieldError
  register: UseFormRegister<ChangePasswordFormValues>
  onToggle: () => void
  showLabel: string
  hideLabel: string
}) {
  const id = `change-password-${name}`
  return (
    <Field data-invalid={Boolean(error)}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      <InputGroup>
        <InputGroupInput
          id={id}
          type={visible ? 'text' : 'password'}
          autoComplete={autoComplete}
          aria-invalid={Boolean(error)}
          {...register(name)}
        />
        <InputGroupAddon className='w-10 flex-none px-3!' align='inline-start'>
          <KeyRound />
        </InputGroupAddon>
        <InputGroupAddon className='w-10 flex-none px-2! has-[>button]:mr-0!' align='inline-end'>
          <InputGroupButton
            type='button'
            size='icon-xs'
            aria-label={visible ? hideLabel : showLabel}
            onClick={onToggle}
          >
            {visible ? <EyeOff /> : <Eye />}
          </InputGroupButton>
        </InputGroupAddon>
      </InputGroup>
      <FieldError errors={[error]} />
    </Field>
  )
}
