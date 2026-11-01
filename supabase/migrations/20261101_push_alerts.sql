-- Phone (Web Push) alerts to admins when someone asks for access.
-- The VAPID key pair and the hook secret live in Supabase Vault as 'push_config'
-- (JSON: {"secret": "...", "jwk": {...}, "pub": "..."}), created separately and never committed.
create extension if not exists pg_net with schema extensions;
create schema if not exists private;

create table if not exists public.push_subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  endpoint text not null unique,
  p256dh text not null,
  auth text not null,
  device text,
  created_at timestamptz not null default now()
);
alter table public.push_subscriptions enable row level security;
drop policy if exists "push subs own select" on public.push_subscriptions;
drop policy if exists "push subs own insert" on public.push_subscriptions;
drop policy if exists "push subs own update" on public.push_subscriptions;
drop policy if exists "push subs own delete" on public.push_subscriptions;
create policy "push subs own select" on public.push_subscriptions for select using (user_id = auth.uid());
create policy "push subs own insert" on public.push_subscriptions for insert with check (user_id = auth.uid());
create policy "push subs own update" on public.push_subscriptions for update using (user_id = auth.uid()) with check (user_id = auth.uid());
create policy "push subs own delete" on public.push_subscriptions for delete using (user_id = auth.uid());

create or replace function private.push_admins(p_title text, p_body text, p_url text, p_tag text)
returns void language plpgsql security definer set search_path = '' as $$
declare cfg jsonb; subs jsonb;
begin
  select decrypted_secret::jsonb into cfg from vault.decrypted_secrets where name = 'push_config' limit 1;
  if cfg is null then return; end if;
  select coalesce(jsonb_agg(jsonb_build_object('endpoint', s.endpoint, 'p256dh', s.p256dh, 'auth', s.auth)), '[]'::jsonb)
    into subs
    from public.push_subscriptions s join public.profiles p on p.id = s.user_id
    where p.role = 'admin';
  if jsonb_array_length(subs) = 0 then return; end if;
  perform net.http_post(
    url := 'https://beaireadyco-school.pages.dev/api/push',
    body := jsonb_build_object(
      'secret', cfg->>'secret',
      'vapid', jsonb_build_object('jwk', cfg->'jwk', 'pub', cfg->>'pub'),
      'subject', 'mailto:beaireadyco@gmail.com',
      'message', jsonb_build_object('title', p_title, 'body', p_body, 'url', p_url, 'tag', p_tag),
      'subs', subs),
    headers := '{"Content-Type": "application/json"}'::jsonb,
    timeout_milliseconds := 10000);
end $$;
revoke all on function private.push_admins(text, text, text, text) from public, anon, authenticated;

create or replace function private.on_access_request()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if new.status = 'pending' then
    begin
      perform private.push_admins(
        'New access request',
        coalesce(new.full_name, new.email) || ' asked to join BeAIReady AI School. Tap to review.',
        '/?go=approvals',
        'access-' || new.user_id::text);
    exception when others then null;
    end;
  end if;
  return new;
end $$;
drop trigger if exists access_request_push on public.access_requests;
create trigger access_request_push after insert on public.access_requests
  for each row execute function private.on_access_request();

create or replace function public.send_test_push()
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and role = 'admin') then
    raise exception 'not allowed';
  end if;
  perform private.push_admins('Phone alerts are on', 'You will get an alert here when someone asks for access.', '/?go=approvals', 'test');
end $$;
revoke all on function public.send_test_push() from public, anon;
grant execute on function public.send_test_push() to authenticated;
