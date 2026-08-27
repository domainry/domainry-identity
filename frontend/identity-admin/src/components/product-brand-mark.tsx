import { PRODUCT_BRAND } from '@/config/product-brand'

export function ProductBrandMark({ className }: { className: string }) {
  return (
    <img
      src={PRODUCT_BRAND.logoUrl}
      alt=''
      aria-hidden='true'
      className={`object-contain ${className}`}
    />
  )
}
