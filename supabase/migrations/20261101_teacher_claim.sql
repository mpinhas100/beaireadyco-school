-- A person added as a teacher signs in as a teacher, even if they had signed in before as a parent.
create or replace function public.claim_invite()
returns text language plpgsql security definer set search_path to 'public' as $$
declare t record;
begin
  select * into t from public.teachers
   where lower(email) = lower(auth.email()) and (profile_id is null or profile_id = auth.uid())
   limit 1;
  if not found then return null; end if;
  insert into public.profiles (id, role, full_name) values (auth.uid(), 'teacher', t.full_name)
  on conflict (id) do update set role = 'teacher' where public.profiles.role = 'parent';
  update public.teachers set profile_id = auth.uid() where id = t.id;
  return 'teacher';
end $$;
