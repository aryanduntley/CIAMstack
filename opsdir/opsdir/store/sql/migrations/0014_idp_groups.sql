-- Migration 0014: the identity provider's groups decide the members of the teams mapped to them (governance.people,
-- the HTTP API; decision on milestone 7.1). A team (ciamParty under ou=owners) may record the identity provider groups
-- it stands for (ciamIdpGroup '<issuer> <group id>'). Its members are then whoever the provider says, request by
-- request: the API passes the verified token's groups with the person (opsdir.requester_groups, a JSON array), trusted
-- only from the API login like the person itself (0013), and the store finds the teams they name (idp_teams). Recorded
-- membership (ciamMemberOf) still counts for teams with no group and is ignored for mapped ones, so someone removed
-- from the group loses the team's grants with their next token, and a login with no token holds no mapped team (fail
-- closed). Mapped teams count only for a recorded person, never for the API login acting as itself.
-- An approval keeps the mapped teams its approver held (ciamApprovedAs, set by the store like ciamApprovedBy), since
-- the grant check of the approver runs later, when the change is applied by someone else's request.
-- History records the API client a write came through (client: the token's azp or client_id, opsdir.client) and the
-- mapped teams the person held (teams), beside the person (db_user, 0013); empty for writes by a direct login.
-- Mapping a team to groups decides its members, so writing a team's ciamIdpGroup needs the settings action, as
-- people and grants do.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

create function api_session() returns boolean language sql stable set search_path = opsdir, pg_temp as $$
    select coalesce(session_user::text = btrim((select a1(attrs, 'ciamEstateValue') from entry
                     where dn_norm = 'cn=api-login,ou=settings,' || (select min(dn_norm) from suffix))), false)
$$;

create or replace function requester() returns text language plpgsql stable set search_path = opsdir, pg_temp as $$
declare
    who text := nullif(btrim(current_setting('opsdir.requester', true)), '');
begin
    if who is null or not api_session() then
        return session_user::text;
    end if;
    if who !~ '^[a-z_][a-z0-9_]{0,62}$' then
        raise exception 'opsdir: requester % isn''t a login name (lowercase letters, digits and _)', who;
    end if;
    return who;
end $$;

create function requester_groups() returns text[] language plpgsql stable set search_path = opsdir, pg_temp as $$
declare
    raw text := nullif(btrim(current_setting('opsdir.requester_groups', true)), '');
    groups jsonb;
begin
    if raw is null or not api_session() or nullif(btrim(current_setting('opsdir.requester', true)), '') is null then
        return '{}';
    end if;
    begin
        groups := raw::jsonb;
    exception when others then
        raise exception 'opsdir: the requester''s groups aren''t a JSON array of strings';
    end;
    if jsonb_typeof(groups) <> 'array'
       or exists (select 1 from jsonb_array_elements(groups) g where jsonb_typeof(g) <> 'string') then
        raise exception 'opsdir: the requester''s groups aren''t a JSON array of strings';
    end if;
    return array(select jsonb_array_elements_text(groups));
end $$;

create function requester_client() returns text language plpgsql stable set search_path = opsdir, pg_temp as $$
declare
    client text := nullif(btrim(current_setting('opsdir.client', true)), '');
begin
    if client is null or not api_session() then
        return null;
    end if;
    if length(client) > 256 or client ~ '[[:cntrl:]]' then
        raise exception 'opsdir: API client % isn''t a plain identifier (256 characters at most)', left(client, 40);
    end if;
    return client;
end $$;

-- The names (cn) of the teams recording one of the groups.
create function idp_teams(p_groups text[]) returns text[] language sql stable set search_path = opsdir, pg_temp as $$
    select coalesce(array_agg(a1(e.attrs, 'cn') order by e.dn_norm), '{}') from entry e
     where 'ciamParty' = any (e.object_classes)
       and parent_dn(e.dn_norm) = 'ou=owners,' || (select min(dn_norm) from suffix)
       and aall(e.attrs, 'ciamIdpGroup') && p_groups
$$;

-- The mapped teams the requester holds: none unless they are a recorded person.
create function requester_teams() returns text[] language plpgsql stable set search_path = opsdir, pg_temp as $$
declare
    groups text[] := requester_groups();
begin
    if cardinality(groups) = 0 or not exists (
           select 1 from entry where dn_norm = 'cn=' || lower(requester()) || ',ou=people,'
                                               || (select min(dn_norm) from suffix)
                                 and 'ciamPerson' = any (object_classes)) then
        return '{}';
    end if;
    return idp_teams(groups);
end $$;

alter table entry_history add column client text;
alter table entry_history add column teams text[];
alter table entry_history alter column client set default requester_client();
alter table entry_history alter column teams set default requester_teams();

-- A login's grants: theirs, their recorded teams that map no group, and the mapped teams given (p_mapped, names).
create function grant_holds(p_login text, p_action text, p_env text, p_teams text[], p_mapped text[])
    returns boolean language plpgsql stable set search_path = opsdir, pg_temp as $$
declare root text := (select min(dn_norm) from suffix); me text[];
begin
    me := array['cn=' || lower(p_login) || ',ou=people,' || root] ||
          coalesce((select array(select norm_dn(x) from unnest(aall(attrs, 'ciamMemberOf')) x
                                  where not exists (select 1 from entry t where t.dn_norm = norm_dn(x)
                                                                            and t.attrs ? 'ciamIdpGroup'))
                      from entry where dn_norm = 'cn=' || lower(p_login) || ',ou=people,' || root), '{}') ||
          array(select 'cn=' || lower(n) || ',ou=owners,' || root from unnest(coalesce(p_mapped, '{}')) n);
    return exists (
        select 1 from entry g
         where 'ciamGrant' = any (g.object_classes)
           and g.attrs -> 'ciamGrantAction' ? p_action
           and array(select norm_dn(x) from unnest(aall(g.attrs, 'ciamGrantee')) x) && me
           and (cardinality(aall(g.attrs, 'ciamGrantEnvironment')) = 0
                or p_env = any (aall(g.attrs, 'ciamGrantEnvironment')))
           and (cardinality(aall(g.attrs, 'ciamGrantOwner')) = 0
                or array(select norm_dn(x) from unnest(aall(g.attrs, 'ciamGrantOwner')) x) && p_teams));
end $$;

create or replace function change_approval() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root   text := (select min(dn_norm) from suffix);
    who    text := requester();
    status text := a1(new.attrs, 'ciamChangeStatus');
    was    text;
    author text;
    held   text[];
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
        held := requester_teams();
        new.attrs := jsonb_set(new.attrs, '{ciamApprovedBy}', jsonb_build_array(who));
        new.attrs := case when cardinality(held) = 0 then new.attrs - 'ciamApprovedAs'
                          else jsonb_set(new.attrs, '{ciamApprovedAs}', to_jsonb(held)) end;
    elsif tg_op = 'UPDATE' and old.attrs ? 'ciamApprovedBy' then
        new.attrs := jsonb_set(new.attrs, '{ciamApprovedBy}', old.attrs -> 'ciamApprovedBy');
        new.attrs := case when old.attrs ? 'ciamApprovedAs'
                          then jsonb_set(new.attrs, '{ciamApprovedAs}', old.attrs -> 'ciamApprovedAs')
                          else new.attrs - 'ciamApprovedAs' end;
    else
        new.attrs := new.attrs - 'ciamApprovedBy' - 'ciamApprovedAs';
    end if;
    return new;
end $$;

create or replace function grant_area_guard() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root text := (select min(dn_norm) from suffix);
    chg text := nullif(current_setting('opsdir.change_id', true), '');
    who text := requester();
    target text; attrs jsonb; env text; teams text[]; act text; approver text; approved_as text[];
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
                  or target like '%ou=settings,' || root
                  or (parent_dn(target) = 'ou=owners,' || root
                      and case tg_op when 'INSERT' then new.attrs ? 'ciamIdpGroup'
                                     when 'DELETE' then old.attrs ? 'ciamIdpGroup'
                                     else old.attrs -> 'ciamIdpGroup' is distinct from new.attrs -> 'ciamIdpGroup' end)
                then 'settings' else 'apply' end;
    if not grant_holds(who, act, env, teams, requester_teams()) then
        raise exception 'opsdir: % may not % %: no grant gives them % there (opsdir report grants)',
            who, act, target, act;
    end if;
    select a1(c.attrs, 'ciamApprovedBy'), aall(c.attrs, 'ciamApprovedAs') into approver, approved_as from entry c
     where c.dn_norm = 'cn=' || lower(chg) || ',ou=changes,' || root;
    if approver is null or not grant_holds(approver, 'approve', env, teams, approved_as) then
        raise exception 'opsdir: change % was approved by %, who may not approve %: no grant gives them approve there',
            chg, coalesce(approver, 'nobody recorded'), target;
    end if;
    return coalesce(new, old);
end $$;

drop function grant_holds(text, text, text, text[]);
