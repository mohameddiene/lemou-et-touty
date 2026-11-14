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
