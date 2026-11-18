'use client'
import DOMPurify from 'isomorphic-dompurify'

export default function Markdown({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
}
