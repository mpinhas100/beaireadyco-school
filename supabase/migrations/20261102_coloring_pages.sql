-- Printable Coloring Pages: admin uploads, every signed-in member can view and download.
create table if not exists public.coloring_pages (
  id uuid primary key default gen_random_uuid(),
  title text not null check (length(title) between 1 and 120),
  file_path text not null,
  thumb_path text,
  sort_order int not null default 0,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);
alter table public.coloring_pages enable row level security;
drop policy if exists "coloring read members" on public.coloring_pages;
drop policy if exists "coloring admin write" on public.coloring_pages;
create policy "coloring read members" on public.coloring_pages for select
  using (exists (select 1 from public.profiles p where p.id = auth.uid()));
create policy "coloring admin write" on public.coloring_pages for all
  using (public.current_role_name() = 'admin') with check (public.current_role_name() = 'admin');

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('coloring', 'coloring', false, 20971520, array['application/pdf', 'image/jpeg'])
on conflict (id) do nothing;

drop policy if exists "coloring files read members" on storage.objects;
drop policy if exists "coloring files admin insert" on storage.objects;
drop policy if exists "coloring files admin update" on storage.objects;
drop policy if exists "coloring files admin delete" on storage.objects;
create policy "coloring files read members" on storage.objects for select to authenticated
  using (bucket_id = 'coloring' and exists (select 1 from public.profiles p where p.id = auth.uid()));
create policy "coloring files admin insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'coloring' and public.current_role_name() = 'admin');
create policy "coloring files admin update" on storage.objects for update to authenticated
  using (bucket_id = 'coloring' and public.current_role_name() = 'admin');
create policy "coloring files admin delete" on storage.objects for delete to authenticated
  using (bucket_id = 'coloring' and public.current_role_name() = 'admin');
