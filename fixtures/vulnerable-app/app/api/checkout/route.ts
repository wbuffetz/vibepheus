import Stripe from 'stripe'
import { NextResponse } from 'next/server'
import { createSupabaseServer } from '@/lib/supabase-server'

const stripe = new Stripe('sk_live_51FAKEFAKEFAKEFAKEFAKEFAKE00testonly')

export async function POST(req: Request) {
  const supabase = createSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { priceId } = await req.json()
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: 'https://example.com/success',
  })
  return NextResponse.json({ url: session.url })
}
