-- New Google sign-ins no longer get an automatic parent account.
-- They must request access and be approved by the admin (request_access / approve_access).
drop trigger if exists on_auth_user_created on auth.users;
