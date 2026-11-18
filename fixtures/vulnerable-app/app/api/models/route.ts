import { NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabase-admin'

export async function POST(req: Request) {
  const { modelId, prompt } = await req.json()
  const { data: model } = await supabaseAdmin.from('models').select('*').eq('id', modelId).single()
  const res = await fetch(`${model.base_url}/chat/completions`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${model.api_key}` },
    body: JSON.stringify({ messages: [{ role: 'user', content: prompt }] }),
  })
  return NextResponse.json(await res.json())
}
