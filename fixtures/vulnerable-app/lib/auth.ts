import { createSupabaseServer } from '@/lib/supabase-server'

export async function requireUser() {
  const supabase = createSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Response('Unauthorized', { status: 401 })
  return { supabase, user }
}
