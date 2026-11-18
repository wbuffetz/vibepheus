import { NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabase-admin'

// Lets users chat with their own saved "custom model" (an OpenAI-compatible endpoint + API key).
export async function POST(req: Request) {
  const { customModelId, messages } = await req.json()

  const { data: model, error } = await supabaseAdmin
    .from('custom_models')
    .select('*')
    .eq('id', customModelId)
    .single()
  if (!model) return NextResponse.json({ error: error?.message }, { status: 404 })

  const res = await fetch(`${model.base_url}/chat/completions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${model.api_key}` },
    body: JSON.stringify({ model: model.model_name, messages, stream: false }),
  })
  return NextResponse.json(await res.json())
}
