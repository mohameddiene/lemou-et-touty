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
