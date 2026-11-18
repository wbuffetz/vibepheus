create table public.custom_models (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) default auth.uid(),
  name text not null,
  base_url text not null,
  model_name text not null,
  api_key text not null
);
alter table public.custom_models enable row level security;

create policy "Users manage own models" on public.custom_models
  for all to authenticated using (auth.uid() = user_id) with check (auth.uid() = user_id);
