import { createContext, useContext, useEffect, useState, useMemo } from 'react'
import { getCookie, setCookie, removeCookie } from '@/lib/cookies'

type Theme = 'dark' | 'light' | 'system'
type ResolvedTheme = Exclude<Theme, 'system'>
/** Skin overlays shipped in src/styles/tokens/theme-*.css ('default' = no overlay). */
export type Palette = 'default' | 'graphite' | 'fresh' | 'violet' | 'forest'

const DEFAULT_THEME = 'light'
const DEFAULT_PALETTE: Palette = 'default'
const PALETTES: Palette[] = ['default', 'graphite', 'fresh', 'violet', 'forest']
const THEME_COOKIE_NAME = 'vite-shadcn-ui-theme'
const PALETTE_COOKIE_NAME = 'vite-shadcn-ui-palette'
const THEME_COOKIE_MAX_AGE = 60 * 60 * 24 * 365 // 1 year

type ThemeProviderProps = {
  children: React.ReactNode
  defaultTheme?: Theme
  storageKey?: string
}

type ThemeProviderState = {
  defaultTheme: Theme
  resolvedTheme: ResolvedTheme
  theme: Theme
  setTheme: (theme: Theme) => void
  resetTheme: () => void
  palette: Palette
  palettes: readonly Palette[]
  setPalette: (palette: Palette) => void
}

const initialState: ThemeProviderState = {
  defaultTheme: DEFAULT_THEME,
  resolvedTheme: 'light',
  theme: DEFAULT_THEME,
  setTheme: () => null,
  resetTheme: () => null,
  palette: DEFAULT_PALETTE,
  palettes: PALETTES,
  setPalette: () => null,
}

const ThemeContext = createContext<ThemeProviderState>(initialState)

function readStoredPalette(): Palette {
  const stored = getCookie(PALETTE_COOKIE_NAME)
  return PALETTES.includes(stored as Palette)
    ? (stored as Palette)
    : DEFAULT_PALETTE
}

export function ThemeProvider({
  children,
  defaultTheme = DEFAULT_THEME,
  storageKey = THEME_COOKIE_NAME,
  ...props
}: ThemeProviderProps) {
  const [theme, _setTheme] = useState<Theme>(
    () => (getCookie(storageKey) as Theme) || defaultTheme
  )
  const [palette, _setPalette] = useState<Palette>(readStoredPalette)

  // Optimized: Memoize the resolved theme calculation to prevent unnecessary re-computations
  const resolvedTheme = useMemo((): ResolvedTheme => {
    if (theme === 'system') {
      return window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light'
    }
    return theme as ResolvedTheme
  }, [theme])

  useEffect(() => {
    const root = window.document.documentElement
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)')

    const applyTheme = (currentResolvedTheme: ResolvedTheme) => {
      root.classList.remove('light', 'dark') // Remove existing theme classes
      root.classList.add(currentResolvedTheme) // Add the new theme class
      root.dataset.shell = 'console'
      if (palette === 'default') {
        delete root.dataset.theme
      } else {
        root.dataset.theme = palette
      }
    }

    const handleChange = () => {
      if (theme === 'system') {
        const systemTheme = mediaQuery.matches ? 'dark' : 'light'
        applyTheme(systemTheme)
      }
    }

    applyTheme(resolvedTheme)

    mediaQuery.addEventListener('change', handleChange)

    return () => mediaQuery.removeEventListener('change', handleChange)
  }, [theme, resolvedTheme, palette])

  const setTheme = (theme: Theme) => {
    setCookie(storageKey, theme, THEME_COOKIE_MAX_AGE)
    _setTheme(theme)
  }

  const resetTheme = () => {
    removeCookie(storageKey)
    _setTheme(defaultTheme)
  }

  const setPalette = (nextPalette: Palette) => {
    setCookie(PALETTE_COOKIE_NAME, nextPalette, THEME_COOKIE_MAX_AGE)
    _setPalette(nextPalette)
  }

  const contextValue = {
    defaultTheme,
    resolvedTheme,
    resetTheme,
    theme,
    setTheme,
    palette,
    palettes: PALETTES,
    setPalette,
  }

  return (
    <ThemeContext value={contextValue} {...props}>
      {children}
    </ThemeContext>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useTheme = () => {
  const context = useContext(ThemeContext)

  if (!context) throw new Error('useTheme must be used within a ThemeProvider')

  return context
}
