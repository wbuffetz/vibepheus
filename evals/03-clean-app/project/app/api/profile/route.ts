import { NextResponse } from 'next/server'
import { createSupabaseServer } from '@/lib/supabase-server'

export async function GET() {
  const supabase = await createSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { data } = await supabase.from('profiles').select('display_name, bio').eq('id', user.id).single()
  return NextResponse.json(data)
}

export async function PATCH(req: Request) {
  const supabase = await createSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const body = await req.json()
  const display_name = String(body.display_name ?? '').slice(0, 50)
  const bio = String(body.bio ?? '').slice(0, 500)
  const { error } = await supabase.from('profiles').update({ display_name, bio }).eq('id', user.id)
  if (error) return NextResponse.json({ error: 'Could not save' }, { status: 400 })
  return NextResponse.json({ ok: true })
}
