# vibepheus report

Scanned 32 files in `vulnerable-app` (nextjs + Supabase + Firebase).

🔴 5 critical · 🟠 8 high · 🟡 1 medium · 🔵 1 low · ⚪ 4 info

## 🔴 VP-001 .env.local is committed to git

**Where:** `.env.local` · severity critical · confidence high

```
git ls-files lists this file
```

**Why it matters:** The next `git add .` will commit your secrets. If the repo is public, bots find leaked keys within minutes.

**How to fix:** Add `.env*` (and `!.env.example`) to .gitignore. If the file was already committed, remove it with `git rm --cached` and rotate every key in it.

## 🔴 VP-002 NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY is exposed to the browser

**Where:** `.env.local:3` · severity critical · confidence high

```
NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJhbGci…[redacted 216 chars]  (also used in: lib/supabase.ts)
```

**Why it matters:** Variables starting with NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ or PUBLIC_ are copied into the JavaScript sent to every visitor. Anyone can open DevTools and read them.

**How to fix:** Rename it without the public prefix, only use it in server code (API routes, server actions), and rotate the key.

## 🔴 VP-003 Stripe secret key written directly in the code

**Where:** `app/api/checkout/route.ts:5` · severity critical · confidence high

```
const stripe = new Stripe('sk_live_…[redacted 44 chars]')
```

**Why it matters:** Anyone who can see this code (a teammate, a public GitHub repo, or the browser if this file ships to the frontend) can copy the key and use your account.

**How to fix:** Move the key to an environment variable that is NOT prefixed with NEXT_PUBLIC_/VITE_, then rotate (revoke and re-create) the key, because the old one should be treated as leaked.

## 🔴 VP-004 Anyone can read, write this Firebase data

**Where:** `firestore.rules:5` · severity critical · confidence high

```
allow read, write: if true;
```

**Why it matters:** Your Firebase config is public by design, so the rules are the only thing protecting your data. Open rules mean anyone can dump or wipe the database.

**How to fix:** Require sign-in and ownership, e.g. `allow read, write: if request.auth != null && request.auth.uid == userId;`

## 🔴 VP-005 Supabase service_role (admin) key used in browser code

**Where:** `lib/supabase.ts:6` · severity critical · confidence high

```
process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!
```

**Why it matters:** The service_role key ignores every Row Level Security rule. In browser code, any visitor can extract it and read, change or delete your entire database.

**How to fix:** Use the anon key in the browser and fix your RLS policies instead. Keep the service_role key in server-only files (add `import "server-only"`) and rotate it.

## 🟠 VP-006 DELETE app/api/admin/users/route.ts has no authentication check

**Where:** `app/api/admin/users/route.ts:4` · severity high · confidence high

```
export async function DELETE(req: Request) {
```

**Why it matters:** Anyone on the internet can call this endpoint directly with curl. Hiding the button in your UI does not protect the API. This route also uses the Supabase service_role (admin) client, which ignores Row Level Security, so whatever it reads or writes is open to anyone who calls it.

**How to fix:** At the top of the handler, get the current user (e.g. `supabase.auth.getUser()`, `auth()`, `getServerSession()`) and return 401 if there is none. For admin routes, also check the user's role.

## 🟠 VP-007 app/api/generate/route.ts calls OpenAI with no login check and no rate limit

**Where:** `app/api/generate/route.ts:6` · severity high · confidence high

```
export async function POST(req: Request) {
```

**Why it matters:** Every call to this endpoint makes a paid API call (AI, email or SMS) billed to your account. Without a login check and a rate limit, anyone can call it in a loop: a simple script making 10 requests per second makes 864,000 calls a day. People have woken up to bills of thousands of dollars this way.

**How to fix:** Require login, then add a per-user rate limit (e.g. @upstash/ratelimit: 20 requests per minute). Cap output size (max_tokens), and set a monthly spending limit in the provider's dashboard as a safety net.

## 🟠 VP-008 POST app/api/models/route.ts has no authentication check

**Where:** `app/api/models/route.ts:4` · severity high · confidence high

```
export async function POST(req: Request) {
```

**Why it matters:** Anyone on the internet can call this endpoint directly with curl. Hiding the button in your UI does not protect the API. This route also uses the Supabase service_role (admin) client, which ignores Row Level Security, so whatever it reads or writes is open to anyone who calls it.

**How to fix:** At the top of the handler, get the current user (e.g. `supabase.auth.getUser()`, `auth()`, `getServerSession()`) and return 401 if there is none. For admin routes, also check the user's role.

## 🟠 VP-009 Users may be able to access other users' data by changing an ID

**Where:** `app/api/orders/[id]/route.ts:13` · severity high · confidence high

```
.eq('id', params.id)
```

**Why it matters:** This route loads a record by the ID in the URL but never checks that it belongs to the logged-in user. Changing /orders/123 to /orders/124 may show someone else's data.

**How to fix:** Add an ownership filter, e.g. `.eq("id", id).eq("user_id", user.id)`, or query with the user's own client so RLS applies.

## 🟠 VP-010 User content rendered as raw HTML (XSS)

**Where:** `components/Comment.tsx:7` · severity high · confidence high

```
<div dangerouslySetInnerHTML={{ __html: comment.body }} />
```

**Why it matters:** If an attacker puts `<img src=x onerror=...>` into this content, their JavaScript runs in every visitor's browser and can steal sessions.

**How to fix:** Render it as text, or sanitize first: `DOMPurify.sanitize(html)`.

## 🟠 VP-011 Any website can call your API, with credentials enabled

**Where:** `next.config.js:8` · severity high · confidence high

```
{ key: 'Access-Control-Allow-Origin', value: '*' },
```

**Why it matters:** Any website can call your API from a visitor's browser. Combined with credentials, this setup is often "fixed" by reflecting the caller's origin, which lets malicious sites act as your logged-in users.

**How to fix:** Allow only your own domain(s), e.g. `Access-Control-Allow-Origin: https://yourapp.com`, and never combine a wildcard or reflected origin with credentials.

## 🟠 VP-012 Anyone (even logged out) can read every row of public.profiles

**Where:** `supabase/migrations/001_init.sql:7` · severity high · confidence high

```
create policy "profiles are viewable" on public.profiles
```

**Why it matters:** A policy with `using (true)` or `with check (true)` allows access to every row, which is the same as having no protection.

**How to fix:** Restrict the policy to the row owner, e.g. `using (auth.uid() = id)`, or to the `authenticated` role if the data really is shared.

## 🟠 VP-013 Table public.orders has no Row Level Security

**Where:** `supabase/migrations/001_init.sql:10` · severity high · confidence high

```
create table public.orders (
```

**Why it matters:** Supabase tables in the public schema can be queried straight from the browser with the anon key. Without RLS, anyone can read and modify every row.

**How to fix:** Run `alter table <name> enable row level security;` and add policies that only let users access their own rows, e.g. `using (auth.uid() = user_id)`.

## 🟡 VP-014 next@14.1.0 is affected by CVE-2025-29927

**Where:** `package.json:6` · severity medium · confidence high

```
"next": "14.1.0",
```

**Why it matters:** Middleware authorization bypass: attackers can skip middleware with the x-middleware-subrequest header. You have no middleware file today, so you are not directly exposed, but upgrade before you add one.

**How to fix:** Upgrade next to 14.2.25 or later in that release line (or the latest version).

## 🔵 VP-015 Anyone (even logged out) can read every row of public.products

**Where:** `supabase/migrations/002_products.sql:8` · severity low · confidence medium

```
create policy "products are public" on public.products for select using (true);
```

**Why it matters:** No obviously private columns (email, address, user_id...), so this may be intentional public data such as a product catalog. Make sure nothing private is stored here later.

**How to fix:** Restrict the policy to the row owner, e.g. `using (auth.uid() = id)`, or to the `authenticated` role if the data really is shared.

## ⚪ VP-016 app/api/translate/route.ts calls OpenAI using a key the user supplies

**Where:** `app/api/translate/route.ts:5` · severity info · confidence medium

```
export async function POST(req: Request) {
```

**Why it matters:** The API key appears to come from the user (their profile or the request), so abuse spends their money, not yours. Make sure users can only use their own key.

**How to fix:** Require login, then add a per-user rate limit (e.g. @upstash/ratelimit: 20 requests per minute). Cap output size (max_tokens), and set a monthly spending limit in the provider's dashboard as a safety net.

## ⚪ VP-017 app/api/vision/route.ts calls Google Gemini using a key the user supplies

**Where:** `app/api/vision/route.ts:9` · severity info · confidence medium

```
export async function POST(req: Request) {
```

**Why it matters:** The API key appears to come from the user (their profile or the request), so abuse spends their money, not yours. Make sure users can only use their own key.

**How to fix:** Require login, then add a per-user rate limit (e.g. @upstash/ratelimit: 20 requests per minute). Cap output size (max_tokens), and set a monthly spending limit in the provider's dashboard as a safety net.

## ⚪ VP-018 Firebase web API key (public by design)

**Where:** `lib/firebase.ts:4` · severity info · confidence high

```
apiKey: 'AIzaSyFA…[redacted 37 chars]',
```

**Why it matters:** Firebase/Google web API keys are meant to be public. They are only safe if your security rules and API key restrictions are set correctly.

**How to fix:** In Google Cloud Console, restrict the key to your domains and the APIs you use. Make sure your Firebase rules are not open.

## ⚪ VP-019 Any logged-in user can read every row of public.comments

**Where:** `supabase/migrations/001_init.sql:23` · severity info · confidence medium

```
create policy "users read comments" on public.comments
```

**Why it matters:** Fine for shared content (comments, posts). Not fine if this table holds private data.

**How to fix:** Restrict the policy to the row owner, e.g. `using (auth.uid() = id)`, or to the `authenticated` role if the data really is shared.

---
External tools: external: skipped (--no-external)

_Automated checks only. "No findings" means these checks passed, not that the app is secure._

_Generated by [vibepheus](https://github.com/wbuffetz/vibepheus) v0.2.0, made by wbuffetz._
