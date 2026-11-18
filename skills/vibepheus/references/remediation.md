# Remediation guide

Standard fixes for each vibepheus rule. Adapt names to the user's code.

## SECRET_IN_PUBLIC_ENV / HARDCODED_SECRET / SECRET_IN_GIT_HISTORY

1. Move the value into `.env.local` under a name **without** a public prefix:
   ```bash
   # .env.local
   STRIPE_SECRET_KEY=sk_live_...
   SUPABASE_SERVICE_ROLE_KEY=eyJ...
   ```
2. Read it only in server code:
   ```ts
   const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!)
   ```
3. Add the same variable in the hosting dashboard (Vercel → Settings → Environment Variables).
4. **Rotate the key.** Where to do it:
   - Stripe: Dashboard → Developers → API keys → Roll key
   - Supabase: Project Settings → API → generate new JWT secret / API keys
   - OpenAI / Anthropic: API keys page → revoke and create new
   - AWS: IAM → Users → Security credentials → deactivate and delete the access key
   - GitHub: Settings → Developer settings → Tokens → delete

## ENV_FILE_NOT_IGNORED

```gitignore
# .gitignore
.env*
!.env.example
```
If it was already committed:
```bash
git rm --cached .env.local
git commit -m "Stop tracking .env.local"
```
Then rotate every key that was in the file.

## SERVICE_ROLE_IN_CLIENT

Browser code uses the anon key; RLS policies decide what each user can do:
```ts
// lib/supabase/client.ts
import { createBrowserClient } from '@supabase/ssr'
export const supabase = createBrowserClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)
```
Admin work happens in server-only code:
```ts
// lib/supabase/admin.ts
import 'server-only'
import { createClient } from '@supabase/supabase-js'
export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
)
```
If code switched to the service role "because of permission denied errors", the real fix is a correct RLS policy (below).

## RLS_DISABLED / RLS_PERMISSIVE_POLICY

New migration, e.g. `supabase/migrations/<timestamp>_enable_rls.sql`:
```sql
alter table public.orders enable row level security;

create policy "Users read own orders" on public.orders
  for select to authenticated using (auth.uid() = user_id);

create policy "Users create own orders" on public.orders
  for insert to authenticated with check (auth.uid() = user_id);

-- Replace an everyone-can-read policy with an owner-only one
drop policy if exists "profiles are viewable" on public.profiles;
create policy "Users read own profile" on public.profiles
  for select to authenticated using (auth.uid() = id);
```
For update policies, use both `using` and `with check` so users cannot move rows to someone else.

## FIREBASE_OPEN_RULES

```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /users/{userId}/{document=**} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
  }
}
```
Deploy with `firebase deploy --only firestore:rules`.

## API_ROUTE_NO_AUTH

```ts
export async function DELETE(req: Request) {
  const supabase = createSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { data: profile } = await supabase.from('profiles').select('role').eq('id', user.id).single()
  if (profile?.role !== 'admin') return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
  // ...
}
```
Use `getUser()` (verifies with Supabase), not `getSession()` (trusts the cookie), on the server.

## PAID_API_UNPROTECTED (denial of wallet)

Three layers: login, a per-user rate limit, and a spending cap at the provider.

```ts
// lib/ratelimit.ts
import { Ratelimit } from '@upstash/ratelimit'
import { Redis } from '@upstash/redis'

export const aiLimiter = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(20, '1 m'), // 20 requests per minute per user
})
```
```ts
// app/api/generate/route.ts
export async function POST(req: Request) {
  const supabase = await createSupabaseServer()
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })

  const { success } = await aiLimiter.limit(user.id)
  if (!success) return NextResponse.json({ error: 'Too many requests' }, { status: 429 })

  const { prompt } = await req.json()
  const completion = await openai.chat.completions.create({
    model: 'gpt-4o-mini',
    max_tokens: 500,                                         // cap the cost of each call
    messages: [{ role: 'user', content: String(prompt).slice(0, 4000) }], // cap input size too
  })
  return NextResponse.json({ text: completion.choices[0].message.content })
}
```
Then, in the provider's dashboard (OpenAI, Anthropic, Twilio...), set a **monthly spending limit** and a usage alert. That's the safety net if everything else fails.

For SMS (Twilio), also limit messages per phone number and per IP, and block premium-rate and unexpected countries. Attackers use "SMS pumping" to send messages to numbers they profit from.

If users bring their own API key, make sure each request can only use the logged-in user's key (filter by `user_id`, never by an ID from the request).

## WEBHOOK_NO_SIGNATURE

```ts
const body = await req.text()
const sig = req.headers.get('stripe-signature')!
const event = stripe.webhooks.constructEvent(body, sig, process.env.STRIPE_WEBHOOK_SECRET!)
```

## POSSIBLE_IDOR

```ts
const { data: order } = await supabase
  .from('orders')
  .select('*')
  .eq('id', params.id)
  .eq('user_id', user.id)   // ownership check
  .single()
if (!order) return NextResponse.json({ error: 'Not found' }, { status: 404 })
```
Return 404 (not 403) so attackers cannot tell which IDs exist.

## CORS_WILDCARD

```js
headers: [
  { key: 'Access-Control-Allow-Origin', value: 'https://yourapp.com' },
  { key: 'Vary', value: 'Origin' },
]
```
Same-origin Next.js apps usually need no CORS headers at all: delete them.

## XSS_UNSANITIZED_HTML

Render as text:
```tsx
<div>{comment.body}</div>
```
Or sanitize if HTML is required:
```tsx
import DOMPurify from 'isomorphic-dompurify'
<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(comment.body) }} />
```

## VULNERABLE_DEPENDENCY

```bash
npm install next@latest
npm audit
```
Run the app and tests after a major-version upgrade.
