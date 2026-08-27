import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from 'react'
import zhCN, { type MessageKey } from '@/locales/zh-CN'
import en from '@/locales/en'

export type { MessageKey }

/* ------------------------------------------------------------------ */
/* Locales                                                             */
/* ------------------------------------------------------------------ */

export const LOCALES = [
  { value: 'zh-CN', label: '中文' },
  { value: 'en', label: 'English' },
] as const

export type Locale = (typeof LOCALES)[number]['value']

const DEFAULT_LOCALE: Locale = 'zh-CN'
const STORAGE_KEY = 'identity-admin-locale'

/** 每个语言一个文件，见 src/locales/*.ts；新增语言时在此注册。 */
const MESSAGES: Record<Locale, Record<MessageKey, string>> = {
  'zh-CN': zhCN,
  en,
}

/* ------------------------------------------------------------------ */
/* Provider & hook                                                     */
/* ------------------------------------------------------------------ */

export type Translate = (
  key: MessageKey,
  params?: Record<string, string | number>
) => string

interface I18nContextValue {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: Translate
}

const I18nContext = createContext<I18nContextValue | null>(null)

function resolveInitialLocale(): Locale {
  if (typeof window === 'undefined') return DEFAULT_LOCALE
  const stored = window.localStorage.getItem(STORAGE_KEY)
  const known = LOCALES.some((item) => item.value === stored)
  return known ? (stored as Locale) : DEFAULT_LOCALE
}

function interpolate(
  template: string,
  params?: Record<string, string | number>
): string {
  if (!params) return template
  return template.replace(/\{(\w+)\}/g, (match, name: string) =>
    name in params ? String(params[name]) : match
  )
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(resolveInitialLocale)

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next)
    window.localStorage.setItem(STORAGE_KEY, next)
    document.documentElement.lang = next
  }, [])

  const t = useCallback<Translate>(
    (key, params) => interpolate(MESSAGES[locale][key] ?? key, params),
    [locale]
  )

  const value = useMemo(() => ({ locale, setLocale, t }), [locale, setLocale, t])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18nContextValue {
  const context = useContext(I18nContext)
  if (!context) throw new Error('useI18n must be used within I18nProvider')
  return context
}
