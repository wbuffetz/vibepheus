create table public.profiles (
  id uuid primary key references auth.users(id),
  email text,
  full_name text
);
alter table public.profiles enable row level security;
create policy "profiles are viewable" on public.profiles
  for select using (true);

create table public.orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  total_cents integer,
  shipping_address text
);

create table public.comments (
  id bigserial primary key,
  user_id uuid references auth.users(id),
  body text
);
alter table public.comments enable row level security;
create policy "users read comments" on public.comments
  for select to authenticated using (true);
create policy "users write own comments" on public.comments
  for insert to authenticated with check (auth.uid() = user_id);
