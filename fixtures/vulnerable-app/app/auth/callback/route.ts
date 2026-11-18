import { NextResponse } from 'next/server'
import { createSupabaseServer } from '@/lib/supabase-server'

export async function GET(request: Request) {
  const code = new URL(request.url).searchParams.get('code')
  if (code) await createSupabaseServer().auth.exchangeCodeForSession(code)
  return NextResponse.redirect(new URL('/dashboard', request.url))
}
