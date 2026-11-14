-- MISE À JOUR (à exécuter UNE fois sur la base actuelle)
-- 1) E-mail de l'admin principal = celui avec lequel tu t'es inscrit dans l'app
update app_settings set value='lebusinessman008@gmail.com' where key='main_admin_email';
-- 2) Prénom + nom
alter table profiles add column if not exists first_name text default '', add column if not exists last_name text default '';
create or replace function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare r text:='user'; f text:=coalesce(new.raw_user_meta_data->>'first_name',''); l text:=coalesce(new.raw_user_meta_data->>'last_name','');
begin
  if lower(new.email)=lower((select value from app_settings where key='main_admin_email')) then r:='main_admin';
  elsif exists(select 1 from admin_invites where email=lower(new.email)) then r:='admin'; delete from admin_invites where email=lower(new.email);
  end if;
  insert into profiles(id,email,full_name,first_name,last_name,role) values(new.id,new.email,coalesce(nullif(trim(f||' '||l),''),new.raw_user_meta_data->>'full_name',''),f,l,r);
  return new;
end $$;
-- 3) Réparer les profils manquants et l'admin principal
insert into profiles(id,email,full_name) select id,email,coalesce(raw_user_meta_data->>'full_name','') from auth.users on conflict do nothing;
update profiles set role='main_admin' where lower(email)=lower((select value from app_settings where key='main_admin_email'));
-- 4) E-mails cachés aux membres
revoke select on profiles from authenticated, anon;
grant select(id,full_name,first_name,last_name,role,created_at) on profiles to authenticated;
create or replace function admin_list() returns table(id uuid,email text,role text) language plpgsql security definer set search_path=public as $$
begin
  if not is_admin() then raise exception 'Interdit'; end if;
  return query select p.id,p.email,p.role from profiles p where p.role<>'user' order by p.created_at;
end $$;
-- 5) Validation des groupes par l'admin
alter table groups add column if not exists status text not null default 'pending' check (status in ('pending','approved'));
update groups set status='approved';
drop policy if exists g_upd on groups; drop policy if exists g_adm on groups;
create policy g_adm on groups for update to authenticated using(is_admin());
create or replace function create_group(p_name text,p_desc text) returns uuid language plpgsql security definer set search_path=public as $$
declare g uuid;
begin
  insert into groups(name,description,owner_id,status) values(p_name,coalesce(p_desc,''),auth.uid(),case when is_admin() then 'approved' else 'pending' end) returning id into g;
  insert into group_members(group_id,user_id,status) values(g,auth.uid(),'active');
  return g;
end $$;
create or replace function join_group(p_code text) returns void language plpgsql security definer set search_path=public as $$
declare g uuid;
begin
  select id into g from groups where code=upper(trim(p_code)) and status='approved';
  if g is null then raise exception 'Code introuvable'; end if;
  insert into group_members(group_id,user_id,status) values(g,auth.uid(),'pending') on conflict do nothing;
end $$;
