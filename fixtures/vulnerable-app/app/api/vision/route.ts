import { GoogleGenerativeAI } from '@google/generative-ai'
import { createClient } from '@supabase/supabase-js'
import { NextResponse } from 'next/server'
import { requireUser } from '@/lib/auth'

// Uses the user's own Gemini key. The service_role key below is unrelated to who pays for AI.
const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!)

export async function POST(req: Request) {
  const { user } = await requireUser()
  const { data: profile } = await admin.from('profiles').select('gemini_api_key').eq('id', user.id).single()
  const genAI = new GoogleGenerativeAI(profile.gemini_api_key)
  const { image } = await req.json()
  const result = await genAI.getGenerativeModel({ model: 'gemini-2.0-flash' }).generateContent(['Describe this image', image])
  return NextResponse.json({ text: result.response.text() })
}
