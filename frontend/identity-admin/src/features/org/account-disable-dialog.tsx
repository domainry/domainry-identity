import { useQuery } from '@tanstack/react-query'
import { DestructiveConfirmationDialog } from '@/components/destructive-confirmation-dialog'
import { identityAccountsApi } from '@/data/api'
import { useUpdateIdentityAccount } from '@/data/hooks'
import type { IdentityAccount } from '@/data/types'
import { useI18n } from '@/lib/i18n'

export function AccountDisableDialog({ account, onClose }: { account: IdentityAccount | null; onClose: () => void }) {
  const { t } = useI18n()
  const update = useUpdateIdentityAccount()
  const impact = useQuery({
    queryKey: ['runtime', 'identity', 'accounts', account?.id ?? '', 'disable-impact'],
    queryFn: () => identityAccountsApi.disableImpact(account!.id),
    enabled: Boolean(account),
  })
  const confirm = async () => {
    if (!account || !impact.data) return
    await update.mutateAsync({ id: account.id, patch: { status: 'disabled' } })
    onClose()
  }
  return (
    <DestructiveConfirmationDialog
      open={Boolean(account)}
      title={t('accounts.disableTitle')}
      description={t('accounts.disableDesc')}
      confirmLabel={t('common.disable')}
      cancelLabel={t('common.cancel')}
      pending={update.isPending}
      confirmDisabled={!impact.data}
      onOpenChange={(open) => { if (!open) onClose() }}
      onConfirm={() => void confirm()}
    >
        {impact.isPending ? <p className='text-sm text-muted-foreground'>{t('accounts.impactLoading')}</p> : null}
        {impact.isError ? <p className='text-sm text-destructive'>{t('dataTable.errorDescription')}</p> : null}
        {impact.data ? <div className='space-y-3 rounded-lg border p-4 text-sm'>
          <p>{t('accounts.disableImpactProfiles', { count: impact.data.profile_bindings.length })}</p>
          {impact.data.profile_bindings.map((binding) => <code key={`${binding.binding_key}:${binding.profile_id}`} className='block rounded bg-muted px-2 py-1'>{binding.binding_key} · {binding.object_key}:{binding.profile_id} · {binding.status}</code>)}
          <p>{t('accounts.disableImpactEntitlements', { count: impact.data.active_entitlement_role_ids.length })}</p>
          {impact.data.active_entitlement_role_ids.map((id) => <code key={id} className='block rounded bg-muted px-2 py-1'>{id}</code>)}
          <p>{impact.data.sessions_will_be_revoked ? t('accounts.disableSessions') : '—'}</p>
          <p>{impact.data.business_facts_preserved ? t('accounts.disableBusinessFactsPreserved') : '—'}</p>
        </div> : null}
    </DestructiveConfirmationDialog>
  )
}
