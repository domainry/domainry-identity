import { describe, expect, it } from 'vitest'
import adminShellSource from './admin-shell.tsx?raw'

describe('AdminShell surface boundary', () => {
  it('does not own Business/Ops pages or use workspace.admin as Runtime Ops authority', () => {
    expect(adminShellSource).not.toContain('SchedulerPage')
    expect(adminShellSource).not.toContain('separateOperationsShell')
    expect(adminShellSource).not.toContain('permission === "workspace.admin"')
    expect(adminShellSource).not.toContain('session.permissions.includes("workspace.admin")')
    expect(adminShellSource).not.toContain('runtime_ops.capability_status.read')
    expect(adminShellSource).not.toContain("session?.permissions")
    expect(adminShellSource).not.toContain("session.permissions")
    expect(adminShellSource).not.toContain(
      'enabled={Boolean(session?.permissions?.includes("workspace.admin"))}',
    )
  })
})
