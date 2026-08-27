import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const frontendRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const manifestPath = path.join(frontendRoot, 'config', 'product-brand.json')
const requiredFields = [
  'name',
  'localizedName',
  'tagline',
  'localizedTagline',
  'description',
  'copyrightYear',
  'copyrightHolder',
  'logoUrl',
  'faviconUrl',
]

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'))
if (manifest.schemaVersion !== 'product-brand-v1') {
  throw new Error(`unsupported product brand schema: ${String(manifest.schemaVersion)}`)
}
for (const field of requiredFields) {
  if (typeof manifest[field] !== 'string' || manifest[field].trim() === '') {
    throw new Error(`product brand field ${field} must be a non-empty string`)
  }
}

console.log(`product brand manifest is valid: ${manifest.name}`)
