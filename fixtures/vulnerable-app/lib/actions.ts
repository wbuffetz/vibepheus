'use server'
import { supabaseAdmin } from '@/lib/supabase-admin'
import { createSupabaseServer } from '@/lib/supabase-server'

export async function deleteMyAccount() {
  const { data: { user } } = await createSupabaseServer().auth.getUser()
  if (!user) throw new Error('Unauthorized')
  await supabaseAdmin.auth.admin.deleteUser(user.id)
}
