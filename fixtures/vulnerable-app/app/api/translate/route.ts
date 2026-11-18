import OpenAI from 'openai'
import { NextResponse } from 'next/server'
import { requireUser } from '@/lib/auth'

export async function POST(req: Request) {
  const { supabase, user } = await requireUser()
  const { data: profile } = await supabase.from('profiles').select('openai_api_key').eq('id', user.id).single()
  const client = new OpenAI({ apiKey: profile.openai_api_key })
  const { text, to } = await req.json()
  const r = await client.chat.completions.create({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: `Translate to ${to}: ${text}` }] })
  return NextResponse.json({ text: r.choices[0].message.content })
}
