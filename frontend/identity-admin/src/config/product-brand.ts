export interface ProductBrand {
  name: string
  localizedName: string
  tagline: string
  localizedTagline: string
  description: string
  consoleTitle: string
  adminDocumentTitle: string
  copyrightNotice: string
  initial: string
  logoUrl: string
  faviconUrl: string
}

interface ProductBrandEnvironment {
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

const DEFAULT_BRAND = __PRODUCT_BRAND_DEFAULTS__

function valueOrDefault(value: string | undefined, fallback: string): string {
  return value?.trim() || fallback
}

export function resolveProductBrand(
  environment: ProductBrandEnvironment,
): ProductBrand {
  const nameOverridden = Boolean(environment.VITE_PRODUCT_BRAND_NAME?.trim())
  const name = valueOrDefault(environment.VITE_PRODUCT_BRAND_NAME, DEFAULT_BRAND.name)
  const consoleTitle = valueOrDefault(
    environment.VITE_PRODUCT_BRAND_CONSOLE_TITLE,
    `${name} Identity`,
  )
  const copyrightHolder = valueOrDefault(
    environment.VITE_PRODUCT_BRAND_COPYRIGHT_HOLDER,
    nameOverridden ? name : DEFAULT_BRAND.copyrightHolder,
  )
  const copyrightYear = valueOrDefault(
    environment.VITE_PRODUCT_BRAND_COPYRIGHT_YEAR,
    DEFAULT_BRAND.copyrightYear,
  )
  const initial = valueOrDefault(
    environment.VITE_PRODUCT_BRAND_INITIAL,
    Array.from(name)[0] ?? '',
  ).toLocaleUpperCase()
  return {
    name,
    localizedName: valueOrDefault(
      environment.VITE_PRODUCT_BRAND_LOCALIZED_NAME,
      nameOverridden ? name : DEFAULT_BRAND.localizedName,
    ),
    tagline: valueOrDefault(environment.VITE_PRODUCT_BRAND_TAGLINE, DEFAULT_BRAND.tagline),
    localizedTagline: valueOrDefault(
      environment.VITE_PRODUCT_BRAND_LOCALIZED_TAGLINE,
      DEFAULT_BRAND.localizedTagline,
    ),
    description: valueOrDefault(
      environment.VITE_PRODUCT_BRAND_DESCRIPTION,
      DEFAULT_BRAND.description,
    ),
    consoleTitle,
    adminDocumentTitle: valueOrDefault(
      environment.VITE_PRODUCT_BRAND_ADMIN_TITLE,
      `${name} Identity Admin`,
    ),
    copyrightNotice: `© ${copyrightYear} ${copyrightHolder}`,
    initial,
    logoUrl: valueOrDefault(environment.VITE_PRODUCT_BRAND_LOGO_URL, DEFAULT_BRAND.logoUrl),
    faviconUrl: valueOrDefault(
      environment.VITE_PRODUCT_BRAND_FAVICON_URL,
      DEFAULT_BRAND.faviconUrl,
    ),
  }
}

export const PRODUCT_BRAND = resolveProductBrand(import.meta.env)

export function applyProductBrandToDocument(
  target: Document,
  brand: ProductBrand = PRODUCT_BRAND,
): void {
  target.title = brand.adminDocumentTitle

  let description = target.querySelector<HTMLMetaElement>('meta[name="description"]')
  if (!description) {
    description = target.createElement('meta')
    description.name = 'description'
    target.head.append(description)
  }
  description.content = brand.description

  let favicon = target.querySelector<HTMLLinkElement>('link[rel~="icon"]')
  if (!favicon) {
    favicon = target.createElement('link')
    favicon.rel = 'icon'
    target.head.append(favicon)
  }
  favicon.href = brand.faviconUrl
  favicon.type = brand.faviconUrl.toLowerCase().includes('.svg')
    ? 'image/svg+xml'
    : 'image/png'
}
