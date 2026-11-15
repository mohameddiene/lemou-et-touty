-- LÉMOU ET TOUTY : base complète (à exécuter une fois dans Supabase > Éditeur SQL)
drop table if exists contributions, announcements, group_members, groups, admin_invites, profiles, app_settings cascade;

create table app_settings(key text primary key, value text);
-- >>> E-MAIL DE L'ADMINISTRATEUR PRINCIPAL (l'acheteur change cette ligne) <<<
insert into app_settings values('main_admin_email','lebusinessman008@gmail.com');
create table admin_invites(email text primary key);
alter table app_settings enable row level security;
alter table admin_invites enable row level security;

create table profiles(id uuid primary key references auth.users on delete cascade, email text, full_name text default '',
  role text not null default 'user' check (role in ('user','admin','main_admin')), created_at timestamptz default now());
create table groups(id uuid primary key default gen_random_uuid(), name text not null, description text default '',
  owner_id uuid not null references profiles(id), code text unique default upper(substr(md5(random()::text),1,6)), created_at timestamptz default now());
create table group_members(group_id uuid references groups on delete cascade, user_id uuid references profiles(id) on delete cascade,
  status text not null default 'pending' check (status in ('pending','active')), joined_at timestamptz default now(), primary key(group_id,user_id));
create table announcements(id uuid primary key default gen_random_uuid(), group_id uuid not null references groups on delete cascade,
  title text not null, body text default '', created_at timestamptz default now());
create table contributions(id uuid primary key default gen_random_uuid(), group_id uuid not null references groups on delete cascade,
  user_id uuid not null references profiles(id) on delete cascade, month date not null, amount int default 0, paid boolean default false,
  unique(group_id,user_id,month));

create or replace function is_admin() returns boolean language sql security definer stable set search_path=public as
$$ select exists(select 1 from profiles where id=auth.uid() and role in ('admin','main_admin')) $$;
create or replace function is_main() returns boolean language sql security definer stable set search_path=public as
$$ select exists(select 1 from profiles where id=auth.uid() and role='main_admin') $$;
create or replace function is_owner(g uuid) returns boolean language sql security definer stable set search_path=public as
$$ select exists(select 1 from groups where id=g and owner_id=auth.uid()) $$;
create or replace function is_member(g uuid) returns boolean language sql security definer stable set search_path=public as
$$ select exists(select 1 from group_members where group_id=g and user_id=auth.uid() and status='active') $$;
create or replace function shares_group(u uuid) returns boolean language sql security definer stable set search_path=public as
$$ select exists(select 1 from group_members a join group_members b using(group_id) where a.user_id=auth.uid() and b.user_id=u) $$;

create or replace function handle_new_user() returns trigger language plpgsql security definer set search_path=public as $$
declare r text:='user';
begin
  if lower(new.email)=lower((select value from app_settings where key='main_admin_email')) then r:='main_admin';
  elsif exists(select 1 from admin_invites where email=lower(new.email)) then r:='admin'; delete from admin_invites where email=lower(new.email);
  end if;
  insert into profiles(id,email,full_name,role) values(new.id,new.email,coalesce(new.raw_user_meta_data->>'full_name',''),r);
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users for each row execute function handle_new_user();

create or replace function create_group(p_name text,p_desc text) returns uuid language plpgsql security definer set search_path=public as $$
declare g uuid;
begin
  insert into groups(name,description,owner_id) values(p_name,coalesce(p_desc,''),auth.uid()) returning id into g;
  insert into group_members(group_id,user_id,status) values(g,auth.uid(),'active');
  return g;
end $$;
create or replace function join_group(p_code text) returns void language plpgsql security definer set search_path=public as $$
declare g uuid;
begin
  select id into g from groups where code=upper(trim(p_code));
  if g is null then raise exception 'Code introuvable'; end if;
  insert into group_members(group_id,user_id,status) values(g,auth.uid(),'pending') on conflict do nothing;
end $$;
create or replace function add_admin(p_email text) returns void language plpgsql security definer set search_path=public as $$
begin
  if not is_main() then raise exception 'Réservé à l’administrateur principal'; end if;
  update profiles set role='admin' where lower(email)=lower(p_email) and role='user';
  if not found then insert into admin_invites values(lower(p_email)) on conflict do nothing; end if;
end $$;
create or replace function remove_admin(p_id uuid) returns void language plpgsql security definer set search_path=public as $$
begin
  if not is_main() then raise exception 'Réservé à l’administrateur principal'; end if;
  update profiles set role='user' where id=p_id and role='admin';
end $$;
create or replace function monthly_stats(gid uuid default null)
returns table(r_month text, r_members bigint, r_groups bigint, r_paid bigint) language plpgsql security definer set search_path=public as $$
begin
  if gid is null and not is_admin() then raise exception 'Interdit'; end if;
  if gid is not null and not (is_owner(gid) or is_admin()) then raise exception 'Interdit'; end if;
  return query select to_char(d,'YYYY-MM'),
    (select count(*) from group_members gm where (gid is null or gm.group_id=gid) and gm.status='active' and date_trunc('month',gm.joined_at)=d),
    (select count(*) from groups g where gid is null and date_trunc('month',g.created_at)=d),
    (select coalesce(sum(c.amount),0) from contributions c where (gid is null or c.group_id=gid) and c.paid and date_trunc('month',c.month)=d)
  from generate_series(date_trunc('month',now())-interval '11 months',date_trunc('month',now()),interval '1 month') as d;
end $$;

alter table profiles enable row level security; alter table groups enable row level security;
alter table group_members enable row level security; alter table announcements enable row level security;
alter table contributions enable row level security;

create policy p_sel on profiles for select to authenticated using(id=auth.uid() or is_admin() or shares_group(id));
create policy g_sel on groups for select to authenticated using(is_admin() or exists(select 1 from group_members m where m.group_id=groups.id and m.user_id=auth.uid()));
create policy g_upd on groups for update to authenticated using(owner_id=auth.uid());
create policy g_del on groups for delete to authenticated using(owner_id=auth.uid() or is_admin());
create policy m_sel on group_members for select to authenticated using(user_id=auth.uid() or is_owner(group_id) or is_admin() or is_member(group_id));
create policy m_upd on group_members for update to authenticated using(is_owner(group_id));
create policy m_del on group_members for delete to authenticated using(user_id=auth.uid() or is_owner(group_id) or is_admin());
create policy a_sel on announcements for select to authenticated using(is_member(group_id) or is_owner(group_id) or is_admin());
create policy a_ins on announcements for insert to authenticated with check(is_owner(group_id));
create policy a_del on announcements for delete to authenticated using(is_owner(group_id));
create policy c_sel on contributions for select to authenticated using(user_id=auth.uid() or is_owner(group_id) or is_admin());
create policy c_all on contributions for all to authenticated using(is_owner(group_id)) with check(is_owner(group_id));
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
alter table profiles add column if not exists phone text default '';
create or replace function my_profile() returns table(first_name text,last_name text,phone text) language sql security definer stable set search_path=public as
$$ select p.first_name,p.last_name,p.phone from profiles p where p.id=auth.uid() $$;
create or replace function update_profile(p_first text,p_last text,p_phone text) returns void language plpgsql security definer set search_path=public as $$
begin
  if trim(coalesce(p_first,''))='' or trim(coalesce(p_last,''))='' then raise exception 'Le prénom et le nom sont obligatoires'; end if;
  if coalesce(trim(p_phone),'')<>'' and trim(p_phone) !~ '^\+?[0-9 ]{8,16}$' then raise exception 'Numéro de téléphone invalide'; end if;
  update profiles set first_name=trim(p_first),last_name=trim(p_last),full_name=trim(p_first)||' '||trim(p_last),phone=coalesce(trim(p_phone),'') where id=auth.uid();
end $$;
create or replace function sync_email() returns trigger language plpgsql security definer set search_path=public as $$
begin update profiles set email=new.email where id=new.id; return new; end $$;
drop trigger if exists on_auth_email_changed on auth.users;
create trigger on_auth_email_changed after update of email on auth.users for each row execute function sync_email();
create table if not exists push_subs(endpoint text primary key,user_id uuid not null references profiles(id) on delete cascade,key_p256dh text not null,key_auth text not null,created_at timestamptz default now());
alter table push_subs enable row level security;
create or replace function save_push(p_endpoint text,p_p256dh text,p_auth text) returns void language plpgsql security definer set search_path=public as $$
begin
  insert into push_subs(endpoint,user_id,key_p256dh,key_auth) values(p_endpoint,auth.uid(),p_p256dh,p_auth)
  on conflict(endpoint) do update set user_id=auth.uid(),key_p256dh=excluded.key_p256dh,key_auth=excluded.key_auth;
end $$;
create or replace function push_targets(p_kind text,p_ref text) returns table(endpoint text,key_p256dh text,key_auth text,title text,body text)
language plpgsql security definer set search_path=public as $$
declare agid uuid; atitle text;
begin
  if auth.uid() is null then raise exception 'Interdit'; end if;
  if p_kind='announcement' then
    select an.group_id,an.title into agid,atitle from announcements an where an.id=p_ref::uuid;
    if agid is null or not is_owner(agid) then raise exception 'Interdit'; end if;
    return query select s.endpoint,s.key_p256dh,s.key_auth,('Nouvelle annonce – '||gr.name)::text,atitle::text
      from group_members m join push_subs s on s.user_id=m.user_id join groups gr on gr.id=m.group_id
      where m.group_id=agid and m.status='active' and m.user_id<>auth.uid();
  elsif p_kind='group_approved' then
    if not is_admin() then raise exception 'Interdit'; end if;
    return query select s.endpoint,s.key_p256dh,s.key_auth,'Groupe validé ✅'::text,('Ton groupe « '||gr.name||' » est validé. Tu peux inviter des membres.')::text
      from groups gr join push_subs s on s.user_id=gr.owner_id where gr.id=p_ref::uuid and gr.status='approved';
  elsif p_kind='admin_added' then
    if not is_main() then raise exception 'Interdit'; end if;
    return query select s.endpoint,s.key_p256dh,s.key_auth,'Nouvel administrateur 🛡️'::text,'Tu es maintenant administrateur de Lémou et Touty.'::text
      from profiles p join push_subs s on s.user_id=p.id where lower(p.email)=lower(p_ref) and p.role='admin';
  else raise exception 'Type inconnu'; end if;
end $$;
