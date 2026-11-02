-- Each person can delete messages from their own view (the other person keeps their copy).
alter table public.messages add column if not exists deleted_by_sender boolean not null default false;
alter table public.messages add column if not exists deleted_by_recipient boolean not null default false;
drop policy if exists "messages mark read" on public.messages;
drop policy if exists "messages update own" on public.messages;
create policy "messages update own" on public.messages for update
  using (sender_id = auth.uid() or recipient_id = auth.uid())
  with check (sender_id = auth.uid() or recipient_id = auth.uid());
revoke update on public.messages from authenticated;
grant update (read_at, deleted_by_sender, deleted_by_recipient) on public.messages to authenticated;

create or replace function private.guard_message_update()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  if auth.uid() is null then return new; end if;
  if auth.uid() <> old.recipient_id then
    new.read_at := old.read_at;
    new.deleted_by_recipient := old.deleted_by_recipient;
  end if;
  if auth.uid() <> old.sender_id then
    new.deleted_by_sender := old.deleted_by_sender;
  end if;
  return new;
end $$;
drop trigger if exists message_guard on public.messages;
create trigger message_guard before update on public.messages for each row execute function private.guard_message_update();
