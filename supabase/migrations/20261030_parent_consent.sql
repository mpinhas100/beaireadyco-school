-- Parent consent record (BeAIReadyCo School privacy notice, version 2026-10-30)
create table if not exists public.parent_consents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  email text,
  notice_version text not null,
  consented_at timestamptz not null default now(),
  unique (user_id, notice_version)
);

alter table public.parent_consents enable row level security;

create policy "own consent read" on public.parent_consents
  for select to authenticated using (user_id = auth.uid());

create policy "admin consent read" on public.parent_consents
  for select to authenticated using (public.current_role_name() = 'admin');

create or replace function public.record_consent(p_version text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  insert into public.parent_consents (user_id, email, notice_version)
  values (auth.uid(), auth.email(), p_version)
  on conflict (user_id, notice_version) do nothing;
end $$;

revoke all on function public.record_consent(text) from public;
grant execute on function public.record_consent(text) to authenticated;
