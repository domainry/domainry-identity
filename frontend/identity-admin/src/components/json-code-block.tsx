import { useState } from 'react'
import { Check, Copy } from 'lucide-react'
import { Button } from '@domainry/ui'
import { cn } from '@/lib/utils'

function stringifyJson(value: unknown) {
  if (typeof value === 'string') return value
  return JSON.stringify(value ?? null, null, 2)
}

export function JsonCodeBlock({
  value,
  filename = 'payload.json',
  className,
}: {
  value: unknown
  filename?: string
  className?: string
}) {
  const [copied, setCopied] = useState(false)
  const code = stringifyJson(value)

  async function copy() {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1500)
  }

  return (
    <div className={cn('overflow-hidden rounded-md border bg-muted/30 text-xs', className)}>
      <div className='flex items-center justify-between border-b px-3 py-1.5 text-muted-foreground'>
        <span className='font-mono'>{filename}</span>
        <Button type='button' variant='ghost' size='icon-sm' aria-label='Copy JSON' onClick={copy}>
          {copied ? <Check /> : <Copy />}
        </Button>
      </div>
      <pre className='max-h-56 min-w-max overflow-auto whitespace-pre p-3 font-mono'>{code}</pre>
    </div>
  )
}
