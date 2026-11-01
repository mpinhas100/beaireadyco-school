-- In-app messages between admin, teachers and parents.
-- Who may message whom is decided in the database (message_contacts), not in the app.
create table if not exists public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id) on delete cascade,
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  child_id uuid references public.children(id) on delete set null,
  body text not null check (length(body) between 1 and 4000),
  created_at timestamptz not null default now(),
  read_at timestamptz
);
create index if not exists messages_recipient_idx on public.messages (recipient_id, created_at desc);
create index if not exists messages_sender_idx on public.messages (sender_id, created_at desc);

-- Everyone the signed-in person is allowed to message.
-- kind = 'person' (a parent, teacher or admin) or 'student' (messages go to the student's parent).
create or replace function public.message_contacts()
returns table (id uuid, name text, role text, kind text, child_id uuid, detail text)
language plpgsql stable security definer set search_path = '' as $$
#variable_conflict use_column
declare
  me uuid := auth.uid();
  my_role text;
  my_teacher uuid;
begin
  select p.role into my_role from public.profiles p where p.id = me;
  if my_role is null then return; end if;
  select t.id into my_teacher from public.teachers t where t.profile_id = me limit 1;

  return query
  with pname as (
    select p.id, p.role,
      coalesce(nullif(p.full_name, ''), (select a.full_name from public.access_requests a where a.user_id = p.id limit 1),
               (select a.email from public.access_requests a where a.user_id = p.id limit 1),
               (select t.full_name from public.teachers t where t.profile_id = p.id limit 1), 'User') as name
    from public.profiles p
  ),
  kids as (
    select c.id, c.parent_id, c.nickname, c.first_name, c.last_name, c.group_id, g.name as group_name, g.teacher_id
    from public.children c left join public.groups g on g.id = c.group_id
  ),
  allowed_people as (
    -- admin: everyone
    select pn.id from pname pn where my_role = 'admin' and pn.id <> me
    union
    -- everyone can message the admin(s)
    select pn.id from pname pn where pn.role = 'admin' and pn.id <> me
    union
    -- teacher: parents of children in their classes
    select k.parent_id from kids k where my_role = 'teacher' and my_teacher is not null and k.teacher_id = my_teacher
    union
    -- parent: teachers of their children's classes
    select t.profile_id from kids k join public.teachers t on t.id = k.teacher_id
      where my_role = 'parent' and k.parent_id = me and t.profile_id is not null
    union
    -- anyone who has messaged me, so I can reply
    select m.sender_id from public.messages m where m.recipient_id = me
  )
  select pn.id, pn.name, pn.role, 'person'::text, null::uuid,
    case pn.role
      when 'parent' then coalesce('Parent of ' || (select string_agg(coalesce(k.nickname, k.first_name), ', ') from kids k where k.parent_id = pn.id), 'Parent')
      when 'teacher' then 'Teacher'
      when 'admin' then 'BeAIReadyCo Admin'
      else pn.role end
  from pname pn where pn.id in (select ap.id from allowed_people ap)
  union all
  select k.parent_id, coalesce(k.first_name || coalesce(' ' || left(k.last_name, 1) || '.', ''), k.nickname), 'student', 'student'::text, k.id,
    'Student' || coalesce(' · ' || k.group_name, '') || ' · message goes to the parent'
  from kids k
  where my_role = 'admin'
     or (my_role = 'teacher' and my_teacher is not null and k.teacher_id = my_teacher);
end $$;
revoke all on function public.message_contacts() from public, anon;
grant execute on function public.message_contacts() to authenticated;

create or replace function public.can_message(p_recipient uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.message_contacts() c where c.id = p_recipient and c.kind = 'person')
      or exists (select 1 from public.message_contacts() c where c.id = p_recipient);
$$;
revoke all on function public.can_message(uuid) from public, anon;
grant execute on function public.can_message(uuid) to authenticated;

alter table public.messages enable row level security;
drop policy if exists "messages read own" on public.messages;
drop policy if exists "messages send allowed" on public.messages;
drop policy if exists "messages mark read" on public.messages;
create policy "messages read own" on public.messages for select using (sender_id = auth.uid() or recipient_id = auth.uid());
create policy "messages send allowed" on public.messages for insert with check (sender_id = auth.uid() and public.can_message(recipient_id));
create policy "messages mark read" on public.messages for update using (recipient_id = auth.uid()) with check (recipient_id = auth.uid());
revoke update on public.messages from authenticated;
grant update (read_at) on public.messages to authenticated;

-- Phone alert to the person who receives a message (if they turned on phone alerts).
create or replace function private.push_to(p_user uuid, p_title text, p_body text, p_url text, p_tag text)
returns void language plpgsql security definer set search_path = '' as $$
declare cfg jsonb; subs jsonb;
begin
  select decrypted_secret::jsonb into cfg from vault.decrypted_secrets where name = 'push_config' limit 1;
  if cfg is null then return; end if;
  select coalesce(jsonb_agg(jsonb_build_object('endpoint', s.endpoint, 'p256dh', s.p256dh, 'auth', s.auth)), '[]'::jsonb)
    into subs from public.push_subscriptions s where s.user_id = p_user;
  if jsonb_array_length(subs) = 0 then return; end if;
  perform net.http_post(
    url := 'https://beaireadyco-school.pages.dev/api/push',
    body := jsonb_build_object('secret', cfg->>'secret', 'vapid', jsonb_build_object('jwk', cfg->'jwk', 'pub', cfg->>'pub'),
      'subject', 'mailto:beaireadyco@gmail.com',
      'message', jsonb_build_object('title', p_title, 'body', p_body, 'url', p_url, 'tag', p_tag), 'subs', subs),
    headers := '{"Content-Type": "application/json"}'::jsonb, timeout_milliseconds := 10000);
end $$;
revoke all on function private.push_to(uuid, text, text, text, text) from public, anon, authenticated;

create or replace function private.on_message()
returns trigger language plpgsql security definer set search_path = '' as $$
declare who text;
begin
  select coalesce(nullif(p.full_name, ''), 'Someone') into who from public.profiles p where p.id = new.sender_id;
  begin
    perform private.push_to(new.recipient_id, 'New message from ' || coalesce(who, 'Someone'), left(new.body, 140), '/?go=messages', 'msg-' || new.sender_id::text);
  exception when others then null;
  end;
  return new;
end $$;
drop trigger if exists message_push on public.messages;
create trigger message_push after insert on public.messages for each row execute function private.on_message();
