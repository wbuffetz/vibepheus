create table public.products (
  id text primary key,
  name text,
  description text,
  price_cents integer
);
alter table public.products enable row level security;
create policy "products are public" on public.products for select using (true);
