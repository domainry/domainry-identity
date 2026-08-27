import { useEffect, useState } from 'react'
import { useMutation, useQueries, useQueryClient } from '@tanstack/react-query'
import { Send, ShieldCheck, Upload, X } from 'lucide-react'
import { Badge, Button } from '@domainry/ui'
import { toast } from 'sonner'
import {
  forgetPendingSystemDraft,
  pendingSystemDraftIDs,
  systemChangePlansApi,
  systemDraftSavedEvent,
  type RuntimeChangePlanDraft,
} from '@/data/action-definition-api'
import { useI18n } from '@/lib/i18n'
import { runtimeApiError } from '@/lib/runtime-api'
import { runtimeErrorConstraintMessage } from '@/lib/runtime-error-details'

type DraftTransition = 'review' | 'approve' | 'publish'

export function PendingSystemDrafts() {
  const { t } = useI18n()
  const queryClient = useQueryClient()
  const [planIDs, setPlanIDs] = useState(pendingSystemDraftIDs)
  const [publishIssues, setPublishIssues] = useState<Record<string, string[]>>({})

  useEffect(() => {
    const refresh = () => setPlanIDs(pendingSystemDraftIDs())
    window.addEventListener(systemDraftSavedEvent, refresh)
    window.addEventListener('storage', refresh)
    return () => {
      window.removeEventListener(systemDraftSavedEvent, refresh)
      window.removeEventListener('storage', refresh)
    }
  }, [])

  const drafts = useQueries({
    queries: planIDs.map((planID) => ({
      queryKey: ['runtime', 'change-plan', planID],
      queryFn: () => systemChangePlansApi.get(planID),
      retry: false,
      refetchInterval: 2_000,
    })),
  })
  const transition = useMutation({
    mutationFn: async ({ draft, action }: { draft: RuntimeChangePlanDraft; action: DraftTransition }) => {
      if (action === 'review') return { action, draft: (await systemChangePlansApi.review(draft)).draft }
      if (action === 'approve') return { action, draft: (await systemChangePlansApi.approve(draft)).draft }
      const validation = await systemChangePlansApi.validateForPublish(draft)
      const issues = validation.issues
        .map((issue) => issue.code)
        .filter((code) => code !== 'backend.change_plan.review_required')
      if (issues.length > 0 || (validation.valid && !validation.apply_allowed)) {
        setPublishIssues((current) => ({ ...current, [draft.plan_id]: issues }))
        throw new Error(issues.join(',') || 'backend.change_plan.apply_not_allowed')
      }
      setPublishIssues((current) => {
        const next = { ...current }
        delete next[draft.plan_id]
        return next
      })
      await systemChangePlansApi.publish(draft)
      return { action, draft }
    },
    onSuccess: async ({ action, draft }) => {
      if (action === 'publish') {
        forgetPendingSystemDraft(draft.plan_id)
        await queryClient.invalidateQueries({ queryKey: ['runtime'] })
        return
      }
      queryClient.setQueryData(['runtime', 'change-plan', draft.plan_id], draft)
    },
    onError: (error) => {
      const structured = runtimeApiError(error)
      toast.error(runtimeErrorConstraintMessage(t, structured, error instanceof Error ? error.message : t('dataTable.errorDescription')))
    },
  })
  const visible = drafts.map((query) => query.data).filter((draft): draft is RuntimeChangePlanDraft => Boolean(draft && draft.status !== 'published'))
  if (visible.length === 0) return null

  return (
    <div className='border-b bg-muted/30 px-4 py-2' data-testid='pending-system-drafts'>
      <div className='mx-auto flex max-w-[1600px] flex-col gap-2'>
        {visible.map((draft) => {
          const busy = transition.isPending && transition.variables?.draft.plan_id === draft.plan_id
          const issues = publishIssues[draft.plan_id] ?? []
          return (
            <div key={draft.plan_id} className='flex flex-col gap-1.5 rounded-md border bg-background/70 px-2.5 py-2 text-sm'>
              <div className='flex flex-wrap items-center gap-2'>
                <span className='font-medium'>{t('roles.systemDraft.title')}</span>
                <code className='text-xs text-muted-foreground'>{draft.plan_id}</code>
                <Badge variant='outline'>{t('roles.systemDraft.status', { status: draft.status, revision: draft.revision })}</Badge>
                <span className='min-w-0 flex-1 truncate text-xs text-muted-foreground'>{draft.payload.business_reason}</span>
                {draft.status === 'draft' ? <Button size='sm' disabled={busy} onClick={() => transition.mutate({ draft, action: 'review' })}><Send data-icon='inline-start' />{t('roles.systemDraft.review')}</Button> : null}
                {draft.status === 'in_review' ? <Button size='sm' disabled={busy} onClick={() => transition.mutate({ draft, action: 'approve' })}><ShieldCheck data-icon='inline-start' />{t('roles.systemDraft.approve')}</Button> : null}
                {draft.status === 'approved' ? <Button size='sm' disabled={busy} onClick={() => transition.mutate({ draft, action: 'publish' })}><Upload data-icon='inline-start' />{t('roles.systemDraft.publish')}</Button> : null}
                <Button
                  size='xs'
                  variant='ghost'
                  disabled={busy}
                  aria-label={t('roles.systemDraft.dismiss')}
                  onClick={() => forgetPendingSystemDraft(draft.plan_id)}
                >
                  <X />
                </Button>
              </div>
              {issues.length > 0 ? (
                <div className='flex flex-wrap items-center gap-2 text-xs text-destructive' role='alert'>
                  <span>{issues.includes('backend.change_plan.snapshot_stale')
                    ? t('roles.systemDraft.snapshotStale')
                    : t('roles.systemDraft.publishBlocked')}</span>
                  <code>{issues.join(', ')}</code>
                </div>
              ) : null}
            </div>
          )
        })}
      </div>
    </div>
  )
}
