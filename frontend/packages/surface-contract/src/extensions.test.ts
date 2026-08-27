import { describe, expect, it } from 'vitest'
import {
  mergeDomainryExtension,
} from './index'

describe('project-owned extension overlays', () => {
  it('lets matching user config win while retaining defaults and rejecting unsupported shape', () => {
    const defaults = {
      productTitle: 'System title',
      defaultLocale: 'zh-CN',
      runtime: { surface: 'business_workspace', timeoutMs: 5000 },
      navigation: ['home', 'queue'],
    }
    const merged = mergeDomainryExtension(defaults, {
      productTitle: 'User title',
      runtime: { timeoutMs: 9000, unsupported: true },
      navigation: ['queue'],
      defaultLocale: 42,
      unsupported: 'ignored',
    })

    expect(merged).toEqual({
      productTitle: 'User title',
      defaultLocale: 'zh-CN',
      runtime: { surface: 'business_workspace', timeoutMs: 9000 },
      navigation: ['queue'],
    })
    expect(defaults.productTitle).toBe('System title')
  })
})
