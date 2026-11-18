import { NextResponse } from 'next/server'
import { supabaseAdmin } from '@/lib/supabase-admin'

export async function DELETE(req: Request) {
  const { userId } = await req.json()
  await supabaseAdmin.auth.admin.deleteUser(userId)
  return NextResponse.json({ ok: true })
}
