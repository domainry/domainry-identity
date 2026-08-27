import path from 'path'
import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import productBrandDefaults from '../config/product-brand.json' with { type: 'json' }

function identityAdminSurfaceManifest(): Plugin {
  const forbiddenModuleFragments = [
    '/src/features/objects/',
    '/src/features/profiles/',
    '/src/features/portal/',
    '/src/app.tsx',
    '/packages/portal-kit/',
  ]
  return {
    name: 'identity-admin-surface-manifest',
    generateBundle(_options, bundle) {
      const chunks = Object.values(bundle)
        .filter((item) => item.type === 'chunk')
        .map((chunk) => {
          const modules = Object.keys(chunk.modules)
            .map((moduleID) => moduleID.replaceAll('\\', '/'))
            .sort()
          for (const moduleID of modules) {
            const forbidden = forbiddenModuleFragments.find((fragment) =>
              moduleID.includes(fragment)
            )
            if (forbidden) {
              this.error(
                `platform Admin artifact contains forbidden source-owned module ${moduleID}`,
              )
            }
          }
          return {
            file: chunk.fileName,
            entry: chunk.isEntry,
            dynamic_entry: chunk.isDynamicEntry,
            modules,
          }
        })
      this.emitFile({
        type: 'asset',
        fileName: 'surface-asset-manifest.json',
        source: `${JSON.stringify({
          contract_version: 'domainry-surface-asset-manifest-v1',
          artifact_kind: 'platform_admin',
          allowed_surfaces: ['admin_console'],
          forbidden_module_fragments: forbiddenModuleFragments,
          chunks,
        }, null, 2)}\n`,
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), identityAdminSurfaceManifest()],
  define: {
    __PRODUCT_BRAND_DEFAULTS__: JSON.stringify(productBrandDefaults),
  },
  server: {
    proxy: {
      '/api': {
        target: process.env.IDENTITY_BACKEND_URL ?? 'http://127.0.0.1:8081',
        changeOrigin: true,
        rewrite: (requestPath) => requestPath.replace(/^\/api/, ''),
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
      '@domainry/ui': path.resolve(__dirname, '../packages/ui/src'),
    },
  },
})
