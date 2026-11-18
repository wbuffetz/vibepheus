import { NextResponse } from 'next/server'
import { requireUser } from '@/lib/auth'

export async function PATCH(req: Request) {
  const { supabase, user } = await requireUser()
  const { theme } = await req.json()
  await supabase.from('profiles').update({ theme }).eq('id', user.id)
  return NextResponse.json({ ok: true })
}
