create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) default auth.uid(),
  title text not null,
  body text
);
alter table public.notes enable row level security;

create policy "Users read own notes" on public.notes
  for select to authenticated using (auth.uid() = user_id);
create policy "Users create own notes" on public.notes
  for insert to authenticated with check (auth.uid() = user_id);
create policy "Users update own notes" on public.notes
  for update to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "Users delete own notes" on public.notes
  for delete to authenticated using (auth.uid() = user_id);
