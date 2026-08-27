/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_IDENTITY_API_URL?: string
  readonly VITE_IDENTITY_WORKSPACE_ID?: string
  readonly VITE_PRODUCT_BRAND_NAME?: string
  readonly VITE_PRODUCT_BRAND_CONSOLE_TITLE?: string
  readonly VITE_PRODUCT_BRAND_ADMIN_TITLE?: string
  readonly VITE_PRODUCT_BRAND_COPYRIGHT_HOLDER?: string
  readonly VITE_PRODUCT_BRAND_COPYRIGHT_YEAR?: string
  readonly VITE_PRODUCT_BRAND_INITIAL?: string
  readonly VITE_PRODUCT_BRAND_LOCALIZED_NAME?: string
  readonly VITE_PRODUCT_BRAND_TAGLINE?: string
  readonly VITE_PRODUCT_BRAND_LOCALIZED_TAGLINE?: string
  readonly VITE_PRODUCT_BRAND_DESCRIPTION?: string
  readonly VITE_PRODUCT_BRAND_LOGO_URL?: string
  readonly VITE_PRODUCT_BRAND_FAVICON_URL?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare const __PRODUCT_BRAND_DEFAULTS__: {
  readonly schemaVersion: 'product-brand-v1'
  readonly name: string
  readonly localizedName: string
  readonly tagline: string
  readonly localizedTagline: string
  readonly description: string
  readonly copyrightYear: string
  readonly copyrightHolder: string
  readonly logoUrl: string
  readonly faviconUrl: string
}
