import { describe, expect, it } from 'vitest'
import { resolveProductBrand } from './product-brand'

describe('product brand configuration', () => {
  it('preserves the current display identity by default', () => {
    expect(resolveProductBrand({})).toEqual({
      name: 'Domainry',
      localizedName: '域铸',
      tagline: 'Identity, access, and governance in one place.',
      localizedTagline: '统一管理身份、访问与治理。',
      description: 'Identity administration and access governance console',
      consoleTitle: 'Domainry Identity',
      adminDocumentTitle: 'Domainry Identity Admin',
      copyrightNotice: '© 2026 Domainry',
      initial: 'D',
      logoUrl: '/images/favicon_light.svg',
      faviconUrl: '/images/favicon.svg',
    })
  })

  it('derives a complete display identity from one brand name', () => {
    expect(resolveProductBrand({ VITE_PRODUCT_BRAND_NAME: 'Acme' })).toMatchObject({
      name: 'Acme',
      localizedName: 'Acme',
      consoleTitle: 'Acme Identity',
      adminDocumentTitle: 'Acme Identity Admin',
      copyrightNotice: '© 2026 Acme',
      initial: 'A',
    })
  })

  it('supports deliberate display overrides without accepting blank values', () => {
    expect(resolveProductBrand({
      VITE_PRODUCT_BRAND_NAME: ' Acme ',
      VITE_PRODUCT_BRAND_CONSOLE_TITLE: ' Operations Hub ',
      VITE_PRODUCT_BRAND_ADMIN_TITLE: ' Control Center ',
      VITE_PRODUCT_BRAND_COPYRIGHT_HOLDER: ' Acme Ltd. ',
      VITE_PRODUCT_BRAND_COPYRIGHT_YEAR: ' 2030 ',
      VITE_PRODUCT_BRAND_INITIAL: ' ax ',
      VITE_PRODUCT_BRAND_LOCALIZED_NAME: ' 艾克米 ',
      VITE_PRODUCT_BRAND_TAGLINE: ' Governed operations ',
      VITE_PRODUCT_BRAND_LOCALIZED_TAGLINE: ' 可治理的运营 ',
      VITE_PRODUCT_BRAND_DESCRIPTION: ' Operations platform ',
      VITE_PRODUCT_BRAND_LOGO_URL: ' /brand/logo.svg ',
      VITE_PRODUCT_BRAND_FAVICON_URL: ' /brand/favicon.png ',
    })).toMatchObject({
      name: 'Acme',
      localizedName: '艾克米',
      tagline: 'Governed operations',
      localizedTagline: '可治理的运营',
      description: 'Operations platform',
      consoleTitle: 'Operations Hub',
      adminDocumentTitle: 'Control Center',
      copyrightNotice: '© 2030 Acme Ltd.',
      initial: 'AX',
      logoUrl: '/brand/logo.svg',
      faviconUrl: '/brand/favicon.png',
    })

    expect(resolveProductBrand({ VITE_PRODUCT_BRAND_NAME: '   ' }).name).toBe('Domainry')
  })
})
