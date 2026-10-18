-- Migration 0011: once any grant is recorded (ciamGrant under ou=grants; governance.grants), every write is checked
-- against the areas it touches, in the store, so the rule holds whoever connects and however.
--   The writing login must hold a covering grant of 'apply' ('settings' for what governs the record itself:
--   ou=grants, ou=people, ou=settings), and the change's approver (ciamApprovedBy, recorded by the store) one of
--   'approve'.
--   An entry's area: its environment (cloud/env, from its env=...,cloud=...,ou=environments ancestor; none for the
--   rest of the record) and its teams (ciamOwner and ciamManagedBy, else its environment's).
--   A grant covers it when its environments (none: all) include the area's and its owners (none: all) meet the
--   area's teams. A person holds the grants naming them or a team of theirs (ciamMemberOf).
-- Not checked: the initial load (BOOTSTRAP), change records themselves (their approval rule is 0010's), and the
-- schema owner (current_user able to act as the owner: the migration login after SET ROLE), the database's
-- break-glass; the operations layer still checks every command's grants.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

create function entry_area_env(p_dn_norm text) returns text language sql immutable as $$
    select (regexp_match(p_dn_norm, '(?:^|,)env=([^,]+),cloud=([^,]+),ou=environments,'))[2] || '/' ||
           (regexp_match(p_dn_norm, '(?:^|,)env=([^,]+),cloud=([^,]+),ou=environments,'))[1]
$$;

-- The teams an entry belongs to (norm DNs): its own owners and keeper, else its environment's.
create function entry_area_teams(p_dn_norm text, p_attrs jsonb) returns text[] language plpgsql stable as $$
declare own text[]; env_dn text;
begin
    own := array(select norm_dn(x) from unnest(aall(p_attrs, 'ciamOwner') || aall(p_attrs, 'ciamManagedBy')) x);
    if cardinality(own) > 0 then
        return own;
    end if;
    env_dn := substring(p_dn_norm from '((?:^|,)env=[^,]+,cloud=[^,]+,ou=environments,.*)$');
    env_dn := ltrim(env_dn, ',');
    if env_dn is null or env_dn = p_dn_norm then
        return '{}';
    end if;
    return coalesce((select array(select norm_dn(x) from unnest(aall(attrs, 'ciamOwner') || aall(attrs, 'ciamManagedBy')) x)
                       from entry where dn_norm = env_dn), '{}');
end $$;

-- Whether a login holds a grant of the action covering an area (environment, teams).
create function grant_holds(p_login text, p_action text, p_env text, p_teams text[]) returns boolean
    language plpgsql stable as $$
declare root text := (select min(dn_norm) from suffix); me text[];
begin
    me := array['cn=' || lower(p_login) || ',ou=people,' || root] ||
          coalesce((select array(select norm_dn(x) from unnest(aall(attrs, 'ciamMemberOf')) x) from entry
                     where dn_norm = 'cn=' || lower(p_login) || ',ou=people,' || root), '{}');
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

create function grant_area_guard() returns trigger language plpgsql as $$
declare
    root text := (select min(dn_norm) from suffix);
    chg text := nullif(current_setting('opsdir.change_id', true), '');
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
    if not grant_holds(session_user, act, env, teams) then
        raise exception 'opsdir: % may not % %: no grant gives them % there (opsdir report grants)',
            session_user, act, target, act;
    end if;
    approver := (select a1(c.attrs, 'ciamApprovedBy') from entry c
                  where c.dn_norm = 'cn=' || lower(chg) || ',ou=changes,' || root);
    if approver is null or not grant_holds(approver, 'approve', env, teams) then
        raise exception 'opsdir: change % was approved by %, who may not approve %: no grant gives them approve there',
            chg, coalesce(approver, 'nobody recorded'), target;
    end if;
    return coalesce(new, old);
end $$;

create trigger entry_validate_grant_areas before insert or update on entry
    for each row execute function grant_area_guard();
create trigger entry_guard_delete_grant_areas before delete on entry
    for each row execute function grant_area_guard();
