import { describe, expect, it } from 'vitest'
import adminShellSource from './admin-shell.tsx?raw'

describe('AdminShell surface boundary', () => {
  it('does not own Business/Ops pages or inspect session permissions directly', () => {
    expect(adminShellSource).not.toContain('SchedulerPage')
    expect(adminShellSource).not.toContain('separateOperationsShell')
    expect(adminShellSource).not.toContain('runtime_ops.capability_status.read')
    expect(adminShellSource).not.toContain("session?.permissions")
    expect(adminShellSource).not.toContain("session.permissions")
  })
})
