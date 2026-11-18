import { generateText } from 'ai'
import { openai } from '@ai-sdk/openai'
import { NextResponse } from 'next/server'
import { requireUser } from '@/lib/auth'
import { aiLimiter } from '@/lib/ratelimit'

export async function POST(req: Request) {
  const { user } = await requireUser()
  const { success } = await aiLimiter.limit(user.id)
  if (!success) return NextResponse.json({ error: 'Too many requests' }, { status: 429 })

  const { text } = await req.json()
  const result = await generateText({ model: openai('gpt-4o-mini'), prompt: `Summarize:\n${text}`, maxOutputTokens: 300 })
  return NextResponse.json({ summary: result.text })
}
