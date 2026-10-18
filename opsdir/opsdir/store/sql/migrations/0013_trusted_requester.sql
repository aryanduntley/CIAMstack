-- Migration 0013: the person behind the API server's login (governance.people, the HTTP API).
-- The API server connects with one dedicated login and serves many people: it verifies each request's token, finds
-- the person it names (ciamIdpSubject on their ciamPerson entry) and, per write transaction, tells the store who they
-- are in the opsdir.requester setting (store.postgres.requesting). requester() is who the store attributes a write
-- to: that value when the login is the one the record's api-login estate setting names (cn=api-login,ou=settings,
-- a governed write like any setting), else the login itself (session_user). Any other login setting opsdir.requester
-- is ignored, so a person can't sign as someone else. Fail closed: an API login that sets no requester acts as
-- itself, which holds no grants and isn't a person (so it approves nothing once people are recorded); a requester
-- that isn't a plain login name is refused.
-- Used wherever the store names a person: a change's author and approver (change_approval, 0010), the grant check
-- (grant_area_guard, 0011), history's db_user and entry.modified_by (set by entry_write_requester, which fires after
-- the entry write triggers: BEFORE triggers fire in name order). bootstrap_guard stays about the real login.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

create function requester() returns text language plpgsql stable set search_path = opsdir, pg_temp as $$
declare
    api text := (select a1(attrs, 'ciamEstateValue') from entry
                  where dn_norm = 'cn=api-login,ou=settings,' || (select min(dn_norm) from suffix));
    who text := nullif(btrim(current_setting('opsdir.requester', true)), '');
begin
    if who is null or api is null or session_user::text <> btrim(api) then
        return session_user::text;
    end if;
    if who !~ '^[a-z_][a-z0-9_]{0,62}$' then
        raise exception 'opsdir: requester % isn''t a login name (lowercase letters, digits and _)', who;
    end if;
    return who;
end $$;

alter table entry_history alter column db_user set default requester();
alter table entry alter column modified_by set default requester();

create function entry_requester() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
begin
    new.modified_by := requester();
    return new;
end $$;

create trigger entry_write_requester before insert or update on entry
    for each row execute function entry_requester();

create or replace function change_approval() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root   text := (select min(dn_norm) from suffix);
    who    text := requester();
    status text := a1(new.attrs, 'ciamChangeStatus');
    was    text;
    author text;
begin
    if current_setting('opsdir.change_id', true) = 'BOOTSTRAP' or not ('ciamChange' = any (new.object_classes))
       or parent_dn(new.dn_norm) is distinct from 'ou=changes,' || root then
        return new;
    end if;
    if tg_op = 'INSERT' then
        author := who;
    else
        author := a1(old.attrs, 'ciamAuthor');
        was := a1(old.attrs, 'ciamChangeStatus');
    end if;
    new.attrs := case when author is null then new.attrs - 'ciamAuthor'
                      else jsonb_set(new.attrs, '{ciamAuthor}', jsonb_build_array(author)) end;
    if status = 'applied' and tg_op = 'UPDATE' and was is distinct from 'approved' and was is distinct from 'applied'
    then
        raise exception 'opsdir: change % is %, not approved: a person approves it before it is applied',
            a1(new.attrs, 'cn'), was;
    end if;
    if status in ('approved', 'applied') and (tg_op = 'INSERT' or was not in ('approved', 'applied')) then
        if exists (select 1 from entry where 'ciamPerson' = any (object_classes))
           and not exists (select 1 from entry where dn_norm = 'cn=' || lower(who) || ',ou=people,' || root
                                                 and 'ciamPerson' = any (object_classes)) then
            raise exception 'opsdir: % approves change % but isn''t a recorded person (ou=people)',
                who, a1(new.attrs, 'cn');
        end if;
        if author is not distinct from who and coalesce(upper((
               select a1(attrs, 'ciamEstateValue') from entry
                where dn_norm = 'cn=approval-separation,ou=settings,' || root)), 'TRUE') <> 'FALSE' then
            raise exception 'opsdir: % wrote change % and can''t approve it: someone else approves '
                            '(approval-separation)', who, a1(new.attrs, 'cn');
        end if;
        new.attrs := jsonb_set(new.attrs, '{ciamApprovedBy}', jsonb_build_array(who));
    elsif tg_op = 'UPDATE' and old.attrs ? 'ciamApprovedBy' then
        new.attrs := jsonb_set(new.attrs, '{ciamApprovedBy}', old.attrs -> 'ciamApprovedBy');
    else
        new.attrs := new.attrs - 'ciamApprovedBy';
    end if;
    return new;
end $$;

create or replace function grant_area_guard() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root text := (select min(dn_norm) from suffix);
    chg text := nullif(current_setting('opsdir.change_id', true), '');
    who text := requester();
    target text; attrs jsonb; env text; teams text[]; act text; approver text;
begin
    if chg is null or chg = 'BOOTSTRAP'
       or not exists (select 1 from entry where 'ciamGrant' = any (object_classes))
       or pg_has_role(current_user, (select nspowner from pg_namespace where nspname = 'opsdir'), 'USAGE') then
        return coalesce(new, old);
    end if;
    if tg_op = 'DELETE' then
        target := old.dn_norm; attrs := old.attrs;
    else
        target := new.dn_norm; attrs := new.attrs;
    end if;
    if target like '%,ou=changes,' || root then
        return coalesce(new, old);
    end if;
    env := coalesce(entry_area_env(target), '');
    teams := entry_area_teams(target, attrs);
    act := case when target like '%ou=grants,' || root or target like '%ou=people,' || root
                  or target like '%ou=settings,' || root then 'settings' else 'apply' end;
    if not grant_holds(who, act, env, teams) then
        raise exception 'opsdir: % may not % %: no grant gives them % there (opsdir report grants)',
            who, act, target, act;
    end if;
    approver := (select a1(c.attrs, 'ciamApprovedBy') from entry c
                  where c.dn_norm = 'cn=' || lower(chg) || ',ou=changes,' || root);
    if approver is null or not grant_holds(approver, 'approve', env, teams) then
        raise exception 'opsdir: change % was approved by %, who may not approve %: no grant gives them approve there',
            chg, coalesce(approver, 'nobody recorded'), target;
    end if;
    return coalesce(new, old);
end $$;
