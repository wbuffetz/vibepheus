import { NextResponse } from 'next/server'
import { createSupabaseServer } from '@/lib/supabase-server'

// Uses the logged-in user's client, so Row Level Security decides which notes are visible.
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params
  const supabase = await createSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { data: note } = await supabase.from('notes').select('*').eq('id', id).single()
  if (!note) return NextResponse.json({ error: 'Not found' }, { status: 404 })
  return NextResponse.json(note)
}
