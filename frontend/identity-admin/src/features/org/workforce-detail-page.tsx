import { useState } from 'react'
import { Link, useNavigate } from '@tanstack/react-router'
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Badge,
  Button,
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Field,
  FieldLabel,
  Input,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@domainry/ui'
import { DetailConflictAlert, DetailPageState, isDetailConflictError } from '@/components/detail-page-state'
import { PageShell } from '@/components/page-shell'
import { useGrantWorkforceRole, useWorkforceAssignableRoles, useWorkforceDetail } from '@/data/hooks'
import { displayText } from '@/data/text'
import { useI18n } from '@/lib/i18n'
import { usePermissions } from '@/lib/permissions'

function DetailField({ label, value }: { label: string; value: string }) {
  return <div><dt className='text-xs text-muted-foreground'>{label}</dt><dd className='mt-1 break-words text-sm font-medium'>{value || '—'}</dd></div>
}

export function WorkforceDetailPage({ profileID }: { profileID: string }) {
  const { t } = useI18n()
  const navigate = useNavigate()
  const { has } = usePermissions()
  const detail = useWorkforceDetail(profileID)
  const [roleDialogOpen, setRoleDialogOpen] = useState(false)
  const [roleID, setRoleID] = useState('')
  const [grantReason, setGrantReason] = useState('')
  const [detailConflict, setDetailConflict] = useState<Error | null>(null)
  const [mutationError, setMutationError] = useState<Error | null>(null)
  const assignableRoles = useWorkforceAssignableRoles(profileID, roleDialogOpen)
  const grantRole = useGrantWorkforceRole()
  const backToWorkforce = () => void navigate({ to: '/admin/org/workforce' })
  if (detail.isPending) return <DetailPageState title={t('workforce.detail.title')} />
  if (!detail.data || detail.isError) return <DetailPageState title={t('workforce.detail.title')} error={detail.error} kind={!detail.error ? 'not-found' : undefined} onRetry={() => void detail.refetch()} onBack={backToWorkforce} backLabel={t('workforce.detail.back')} />
  const value = detail.data
  const submitRoleGrant = async () => {
    setMutationError(null)
    try {
      await grantRole.mutateAsync({
        identityUserID: value.profile.identityUserId,
        workforceProfileID: value.profile.id,
        roleID,
        reason: grantReason,
      })
      setDetailConflict(null)
      setRoleDialogOpen(false)
      setRoleID('')
      setGrantReason('')
      await detail.refetch()
    } catch (error) {
      if (isDetailConflictError(error)) {
        setDetailConflict(error instanceof Error ? error : new Error('detail conflict'))
      } else {
        setMutationError(error instanceof Error ? error : new Error(t('dataTable.errorDescription')))
      }
    }
  }
  const reloadLatestWorkforce = async () => {
    const refreshed = await detail.refetch()
    if (refreshed.data) {
      setDetailConflict(null)
      setRoleDialogOpen(false)
    }
  }
  return (
    <PageShell
      title={`${value.profile.workerNo} · ${displayText(t, value.account.name)}`}
      description={t('workforce.detail.desc')}
      actions={<div className='flex gap-2'>
        <Button asChild variant='outline'><Link to='/admin/org/workforce'>{t('workforce.detail.back')}</Link></Button>
		{has('identity.user_role_assignments.assign') ? <Button onClick={() => setRoleDialogOpen(true)}>{t('workforce.detail.grantRole')}</Button> : null}
      </div>}
    >
      {detailConflict && !roleDialogOpen ? <DetailConflictAlert error={detailConflict} onReload={() => void reloadLatestWorkforce()} /> : null}
      <Card>
        <CardHeader className='flex flex-row items-center justify-between gap-3'><CardTitle>{t('workforce.detail.account')}</CardTitle><Button asChild size='sm' variant='outline'><Link to='/admin/security/accounts/$userId' params={{ userId: value.account.id }}>{t('workforce.detail.openAccountSummary')}</Link></Button></CardHeader>
        <CardContent>
          <dl className='grid gap-5 md:grid-cols-2 xl:grid-cols-4'>
            <DetailField label={t('accounts.form.name')} value={displayText(t, value.account.name)} />
            <DetailField label={t('accounts.form.email')} value={value.account.email} />
            <DetailField label={t('accounts.form.phone')} value={value.account.phone} />
            <DetailField label={t('accounts.table.status')} value={value.account.status} />
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>{t('workforce.detail.businessProfiles')}</CardTitle></CardHeader>
        <CardContent className='flex flex-wrap gap-2'>
          {value.businessProfiles.map((profile) => (
            <Badge key={`${profile.bindingKey}:${profile.profileId}`} variant='secondary'>
              {profile.bindingKey} · {profile.objectKey} · {profile.status}
            </Badge>
          ))}
          {value.businessProfiles.length === 0 ? <p className='text-sm text-muted-foreground'>{t('workforce.detail.noBusinessProfiles')}</p> : null}
        </CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>{t('workforce.detail.assignments')}</CardTitle></CardHeader>
        <CardContent>
          <Table>
            <TableHeader><TableRow><TableHead>{t('workforce.form.assignmentID')}</TableHead><TableHead>{t('workforce.form.organizationUnitID')}</TableHead><TableHead>{t('workforce.table.type')}</TableHead><TableHead>{t('workforce.table.status')}</TableHead></TableRow></TableHeader>
            <TableBody>
              {value.assignments.map((assignment) => <TableRow key={assignment.id}><TableCell>{assignment.id}</TableCell><TableCell>{assignment.organizationUnitId}</TableCell><TableCell>{assignment.assignmentType}</TableCell><TableCell>{assignment.status}</TableCell></TableRow>)}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      <Dialog open={roleDialogOpen} onOpenChange={setRoleDialogOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>{t('workforce.detail.grantRole')}</DialogTitle><DialogDescription>{t('workforce.detail.roleEligibility')}</DialogDescription></DialogHeader>
          {detailConflict ? <DetailConflictAlert error={detailConflict} onReload={() => void reloadLatestWorkforce()} /> : null}
          {mutationError ? <Alert variant='destructive'><AlertTitle>{t('detailState.errorTitle')}</AlertTitle><AlertDescription>{mutationError.message}</AlertDescription></Alert> : null}
          <div className='space-y-4'>
            <Field>
              <FieldLabel>{t('workforce.detail.role')}</FieldLabel>
              <Select value={roleID} onValueChange={setRoleID}>
                <SelectTrigger><SelectValue placeholder={t('workforce.detail.selectRole')} /></SelectTrigger>
                <SelectContent>
                  {(assignableRoles.data ?? []).map((role) => <SelectItem key={role.id} value={role.id}>{role.label} · {role.key}</SelectItem>)}
                </SelectContent>
              </Select>
            </Field>
            <Field><FieldLabel>{t('workforce.form.reason')}</FieldLabel><Input value={grantReason} onChange={(event) => setGrantReason(event.target.value)} /></Field>
          </div>
          <DialogFooter>
            <Button variant='outline' onClick={() => setRoleDialogOpen(false)}>{t('common.cancel')}</Button>
            <Button disabled={!roleID || grantRole.isPending} onClick={() => void submitRoleGrant()}>{t('workforce.detail.grantRole')}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </PageShell>
  )
}
