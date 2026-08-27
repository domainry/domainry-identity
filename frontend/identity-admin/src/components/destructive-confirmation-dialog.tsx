import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Button,
  Field,
  FieldDescription,
  FieldLabel,
  Textarea,
} from '@domainry/ui'
import type { ReactNode } from 'react'

type DestructiveConfirmationDialogProps = {
  open: boolean
  title: string
  description: string
  error?: string
  confirmLabel: string
  cancelLabel: string
  pending?: boolean
  destructive?: boolean
  confirmDisabled?: boolean
  children?: ReactNode
  reason?: string
  reasonLabel?: string
  reasonPlaceholder?: string
  reasonDescription?: ReactNode
  reasonRequired?: boolean
  onReasonChange?: (reason: string) => void
  onOpenChange: (open: boolean) => void
  onConfirm: () => void
}

export function DestructiveConfirmationDialog({
  open,
  title,
  description,
  error,
  confirmLabel,
  cancelLabel,
  pending = false,
  destructive = true,
  confirmDisabled = false,
  children,
  reason,
  reasonLabel,
  reasonPlaceholder,
  reasonDescription,
  reasonRequired = false,
  onReasonChange,
  onOpenChange,
  onConfirm,
}: DestructiveConfirmationDialogProps) {
  const missingReason = reasonRequired && !reason?.trim()
  return (
    <AlertDialog open={open} onOpenChange={(nextOpen) => { if (!pending) onOpenChange(nextOpen) }}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        {children}
        {onReasonChange ? (
          <Field>
            {reasonLabel ? <FieldLabel htmlFor='destructive-confirmation-reason'>{reasonLabel}</FieldLabel> : null}
            <Textarea
              id='destructive-confirmation-reason'
              value={reason ?? ''}
              rows={3}
              placeholder={reasonPlaceholder}
              aria-required={reasonRequired}
              onChange={(event) => onReasonChange(event.target.value)}
            />
            {reasonDescription ? <FieldDescription>{reasonDescription}</FieldDescription> : null}
          </Field>
        ) : null}
        {error ? (
          <div role='alert' className='rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm text-destructive'>
            {error}
          </div>
        ) : null}
        <AlertDialogFooter>
          <AlertDialogCancel disabled={pending}>{cancelLabel}</AlertDialogCancel>
          <Button variant={destructive ? 'destructive' : 'default'} disabled={pending || missingReason || confirmDisabled} onClick={onConfirm}>{confirmLabel}</Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
