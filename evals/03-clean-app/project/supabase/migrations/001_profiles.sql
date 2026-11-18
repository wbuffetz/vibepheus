create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  bio text
);
alter table public.profiles enable row level security;

create policy "Users read own profile" on public.profiles
  for select to authenticated using (auth.uid() = id);
create policy "Users update own profile" on public.profiles
  for update to authenticated using (auth.uid() = id) with check (auth.uid() = id);
