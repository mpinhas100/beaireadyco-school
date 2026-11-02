-- Security fixes (Nov 2 2026)
-- 1) approve_access / reject_access: "current_role_name() <> 'admin'" is NULL (not true)
--    for anyone without a profile, so the admin check was skipped. Use IS DISTINCT FROM.
-- 2) Functions that need a signed-in user can no longer be called anonymously.
-- 3) Pin search_path on two helper functions.

create or replace function public.approve_access(p_user uuid, p_role text)
returns void language plpgsql security definer set search_path = public as $$
declare r record;
begin
  if public.current_role_name() is distinct from 'admin' then
    raise exception 'Only the admin can approve accounts';
  end if;
  if p_role not in ('parent', 'teacher', 'staff') then raise exception 'Unknown role'; end if;
  select * into r from public.access_requests where user_id = p_user;
  if not found then raise exception 'No request found'; end if;
  insert into public.profiles (id, role, full_name) values (p_user, p_role, coalesce(r.full_name, r.email))
    on conflict (id) do update set role = excluded.role;
  update public.access_requests set status = 'approved', decided_at = now() where user_id = p_user;
  if p_role = 'teacher' then
    insert into public.teachers (email, full_name, profile_id) values (r.email, coalesce(r.full_name, r.email), p_user)
      on conflict (email) do update set profile_id = excluded.profile_id;
  end if;
end;
$$;

create or replace function public.reject_access(p_user uuid)
returns void language plpgsql security definer set search_path = public as $$
begin
  if public.current_role_name() is distinct from 'admin' then
    raise exception 'Only the admin can reject accounts';
  end if;
  update public.access_requests set status = 'rejected', decided_at = now() where user_id = p_user;
end;
$$;

-- Signed-in only
do $$
declare f text;
begin
  foreach f in array array[
    'public.approve_access(uuid,text)', 'public.reject_access(uuid)', 'public.claim_invite()',
    'public.record_consent(text)', 'public.request_access()',
    'public.redeem_group_invite(text,text,text,text,text,text)',
    'public.staff_assign(text,uuid,uuid,text)', 'public.staff_find_students(text)',
    'public.staff_group_invite(uuid)', 'public.staff_set_student_group(text,uuid)'
  ] loop
    execute format('revoke execute on function %s from public, anon', f);
    execute format('grant execute on function %s to authenticated', f);
  end loop;
  -- Trigger / event-trigger functions are never called directly
  execute 'revoke execute on function public.handle_new_user() from public, anon, authenticated';
  execute 'revoke execute on function public.rls_auto_enable() from public, anon, authenticated';
end $$;

alter function public.assign_student_id() set search_path = public;
alter function public.make_student_id() set search_path = public;
