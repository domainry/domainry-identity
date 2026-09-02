import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { Badge, Button, Card, CardContent, CardDescription, CardHeader, CardTitle, Field, FieldLabel, Input } from '@domainry/ui'
import { identityAccessApi, type IdentityAccessReason, type IdentityGrantSource } from '@/data/api'
import { useI18n } from '@/lib/i18n'

function grantSourceLabel(source: IdentityGrantSource): string {
  return [
    source.type,
    source.role_key || source.role_id,
    source.permission_set_key || source.permission_set_group_key,
    source.assignment_source,
    source.binding_key && source.profile_id ? `${source.binding_key}:${source.profile_id}` : '',
  ].filter(Boolean).join(' · ')
}

function ExplainReasonNode({ reason, depth = 0 }: { reason: IdentityAccessReason; depth?: number }) {
  const { t } = useI18n()
  return (
    <li className='space-y-2 rounded-md border p-3' style={{ marginInlineStart: `${depth * 12}px` }}>
      <div className='flex flex-wrap items-center gap-2'>
        <Badge variant={reason.effect === 'allow' ? 'default' : 'destructive'}>{reason.effect}</Badge>
        <Badge variant='outline'>{reason.layer}</Badge>
        <code className='text-xs'>{reason.code}</code>
        {reason.subject ? <span className='text-xs text-muted-foreground'>{reason.subject}</span> : null}
      </div>
      {reason.details && Object.keys(reason.details).length ? <dl className='grid grid-cols-[max-content_1fr] gap-x-2 text-xs'>{Object.entries(reason.details).map(([key, value]) => <div key={key} className='contents'><dt className='text-muted-foreground'>{key}</dt><dd>{value}</dd></div>)}</dl> : null}
      {reason.sources?.length ? <div className='flex flex-wrap gap-1'>{reason.sources.map((source, index) => <Badge key={`${source.key}:${index}`} variant='secondary'>{grantSourceLabel(source) || source.key}</Badge>)}</div> : null}
      {reason.children?.length ? <ol aria-label={t('effectiveAccessExplain.reasonChildren')} className='space-y-2'>{reason.children.map((child, index) => <ExplainReasonNode key={`${child.layer}:${child.code}:${index}`} reason={child} depth={depth + 1} />)}</ol> : null}
    </li>
  )
}

export function EffectiveAccessExplainCard({ userID }: { userID: string }) {
  const { t } = useI18n()
  const [objectKey, setObjectKey] = useState('')
  const [action, setAction] = useState('')
  const [fieldKey, setFieldKey] = useState('')
  const [recordID, setRecordID] = useState('')
  const explain = useMutation({
    mutationFn: () => identityAccessApi.explain({
      user_id: userID,
      object_key: objectKey.trim(),
      action: action.trim(),
      ...(fieldKey.trim() ? { field_key: fieldKey.trim() } : {}),
      ...(recordID.trim() ? { record_id: recordID.trim() } : {}),
    }),
  })
  const result = explain.data
  return (
    <Card data-testid='effective-access-explain'>
      <CardHeader>
        <CardTitle>{t('effectiveAccessExplain.title')}</CardTitle>
        <CardDescription>{t('effectiveAccessExplain.description')}</CardDescription>
      </CardHeader>
      <CardContent className='space-y-4'>
        <div className='grid gap-3 md:grid-cols-2 xl:grid-cols-4'>
          <Field><FieldLabel htmlFor='explain-object'>{t('effectiveAccessExplain.object')}</FieldLabel><Input id='explain-object' value={objectKey} onChange={(event) => setObjectKey(event.target.value)} placeholder='order' /></Field>
          <Field><FieldLabel htmlFor='explain-action'>{t('effectiveAccessExplain.action')}</FieldLabel><Input id='explain-action' value={action} onChange={(event) => setAction(event.target.value)} placeholder='read' /></Field>
          <Field><FieldLabel htmlFor='explain-field'>{t('effectiveAccessExplain.field')}</FieldLabel><Input id='explain-field' value={fieldKey} onChange={(event) => setFieldKey(event.target.value)} placeholder={t('effectiveAccessExplain.optional')} /></Field>
          <Field><FieldLabel htmlFor='explain-record'>{t('effectiveAccessExplain.record')}</FieldLabel><Input id='explain-record' value={recordID} onChange={(event) => setRecordID(event.target.value)} placeholder={t('effectiveAccessExplain.optional')} /></Field>
        </div>
        <Button disabled={!objectKey.trim() || !action.trim() || explain.isPending} onClick={() => explain.mutate()}>{t('effectiveAccessExplain.run')}</Button>
        {explain.isError ? <p role='alert' className='text-sm text-destructive'>{t('effectiveAccessExplain.failed')}</p> : null}
        {result ? <div className='space-y-3' role='status'>
          <div className='flex flex-wrap items-center gap-2'>
            <Badge variant={result.allowed ? 'default' : 'destructive'}>{result.allowed ? t('effectiveAccessExplain.allowed') : t('effectiveAccessExplain.denied')}</Badge>
            <span className='text-xs text-muted-foreground'>{t('effectiveAccess.revision', { revision: result.authorization_revision || '-' })}</span>
          </div>
          <ol><ExplainReasonNode reason={result.reason} /></ol>
        </div> : null}
      </CardContent>
    </Card>
  )
}
