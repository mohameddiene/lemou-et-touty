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
