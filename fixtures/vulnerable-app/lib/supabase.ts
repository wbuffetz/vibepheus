import { createClient } from '@supabase/supabase-js'

// "it kept saying permission denied so I used the other key"
export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
)
