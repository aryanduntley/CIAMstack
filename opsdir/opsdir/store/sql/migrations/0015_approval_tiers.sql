-- Migration 0015: risk-tiered approval (governance; decision on milestone 129). The approvals-required estate setting
-- says how many distinct people must approve a change, per environment ('<cloud/env or *>=<1-9>, ...'; '*' for
-- everything not listed; empty or unset: 1). Each approval is recorded once per person (ciamApprovals, set by the store
-- like ciamApprovedBy, never the author while approval-separation is on), with the identity provider-mapped teams the
-- approver held ('<login> <team>' in ciamApprovedAs). A change stays proposed until it has the approvals its proposed
-- records' environments need (the most any of them needs; '*' when it proposes nothing), and its approvals are cleared
-- when the records it proposes change before it is approved. Every entry written under a change also needs the
-- approvals its own environment needs, and, once grants exist, that many of the approvers holding approve there; the
-- schema owner stays the database's break-glass. History keeps each approval (one write each).
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

-- How many approvals an environment ('cloud/env', '' for what lies in none) needs; a malformed setting refuses.
create function required_approvals(p_env text) returns int language plpgsql stable
    set search_path = opsdir, pg_temp as $$
declare
    raw text := (select a1(attrs, 'ciamEstateValue') from entry
                  where dn_norm = 'cn=approvals-required,ou=settings,' || (select min(dn_norm) from suffix));
    part text; k text; v text; star int := 1; hit int;
begin
    if raw is null or btrim(raw) = '' then
        return 1;
    end if;
    foreach part in array string_to_array(raw, ',') loop
        k := btrim(split_part(part, '=', 1));
        v := btrim(split_part(part, '=', 2));
        if k = '' or v !~ '^[1-9]$' or (k <> '*' and k !~ '^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$') then
            raise exception 'opsdir: setting approvals-required: `%` isn''t <cloud/env or *>=<1-9>', btrim(part);
        end if;
        if k = '*' then
            star := v::int;
        elsif lower(k) = lower(coalesce(p_env, '')) then
            hit := v::int;
        end if;
    end loop;
    return coalesce(hit, star);
end $$;

-- How many approvals a change needs: the most its proposed records' environments need ('*' when it proposes none).
-- The records are LDIF (folded lines unfolded first); a record whose DN isn't plain text counts as '*' here, and the
-- write-time guard below still holds every entry written to its own environment's number.
create function change_needs(p_attrs jsonb) returns int language sql stable set search_path = opsdir, pg_temp as $$
    select coalesce(max(required_approvals(coalesce(entry_area_env(norm_dn(btrim(m[1]))), ''))),
                    required_approvals(''))
      from unnest(aall(p_attrs, 'ciamChangeRecords')) r,
           lateral regexp_matches(replace(replace(r, E'\r\n', E'\n'), E'\n ', ''), '(?:^|\n)dn: *([^\n]*)', 'g') m
$$;

-- The approvers of a change: ciamApprovals, or its approver from before 0015.
create function change_approvers(p_attrs jsonb) returns text[] language sql immutable as $$
    select case when cardinality(aall(p_attrs, 'ciamApprovals')) > 0 then aall(p_attrs, 'ciamApprovals')
                when p_attrs ? 'ciamApprovedBy' then array[a1(p_attrs, 'ciamApprovedBy')]
                else '{}'::text[] end
$$;

-- The mapped teams one approver held ('<login> <team>' values; a bare team name, from 0014, is the approver's).
create function approver_teams(p_attrs jsonb, p_login text) returns text[] language sql immutable as $$
    select coalesce(array_agg(case when position(' ' in v) > 0 then substr(v, position(' ' in v) + 1) else v end), '{}')
      from unnest(aall(p_attrs, 'ciamApprovedAs')) v
     where (position(' ' in v) > 0 and split_part(v, ' ', 1) = p_login)
        or (position(' ' in v) = 0 and a1(p_attrs, 'ciamApprovedBy') = p_login)
$$;

create or replace function change_approval() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root      text := (select min(dn_norm) from suffix);
    who       text := requester();
    status    text := a1(new.attrs, 'ciamChangeStatus');
    was       text;
    author    text;
    approvals text[];
    held      text[];
    as_teams  text[];
    need      int;
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
        approvals := case when tg_op = 'UPDATE' then aall(old.attrs, 'ciamApprovals') else '{}' end;
        as_teams := case when tg_op = 'UPDATE' then aall(old.attrs, 'ciamApprovedAs') else '{}' end;
        if who = any (approvals) then
            raise exception 'opsdir: % already approved change %: the next approval is someone else''s',
                who, a1(new.attrs, 'cn');
        end if;
        held := requester_teams();
        approvals := approvals || who;
        as_teams := as_teams || array(select who || ' ' || t from unnest(held) t);
        need := change_needs(new.attrs);
        new.attrs := jsonb_set(new.attrs, '{ciamApprovals}', to_jsonb(approvals));
        new.attrs := case when cardinality(as_teams) = 0 then new.attrs - 'ciamApprovedAs'
                          else jsonb_set(new.attrs, '{ciamApprovedAs}', to_jsonb(as_teams)) end;
        if cardinality(approvals) < need then              -- not yet: the change waits for more approvals
            new.attrs := jsonb_set(new.attrs, '{ciamChangeStatus}', '["proposed"]') - 'ciamApprovedBy';
        else
            new.attrs := jsonb_set(new.attrs, '{ciamApprovedBy}', jsonb_build_array(who));
        end if;
    elsif tg_op = 'UPDATE' and (old.attrs -> 'ciamChangeRecords' is not distinct from new.attrs -> 'ciamChangeRecords'
                                or was in ('approved', 'applied')) then
        new.attrs := new.attrs - 'ciamApprovedBy' - 'ciamApprovals' - 'ciamApprovedAs';
        new.attrs := new.attrs || jsonb_strip_nulls(jsonb_build_object(
            'ciamApprovedBy', old.attrs -> 'ciamApprovedBy', 'ciamApprovals', old.attrs -> 'ciamApprovals',
            'ciamApprovedAs', old.attrs -> 'ciamApprovedAs'));
    else                                                    -- new, or what it proposes changed: approvals start over
        new.attrs := new.attrs - 'ciamApprovedBy' - 'ciamApprovals' - 'ciamApprovedAs';
    end if;
    return new;
end $$;

-- Every entry written under a change needs the approvals its environment needs (the schema owner excepted).
create function change_approvals_guard() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root text := (select min(dn_norm) from suffix);
    chg text := nullif(current_setting('opsdir.change_id', true), '');
    target text; env text; need int; c jsonb; have int;
begin
    if chg is null or chg = 'BOOTSTRAP'
       or pg_has_role(current_user, (select nspowner from pg_namespace where nspname = 'opsdir'), 'USAGE') then
        return coalesce(new, old);
    end if;
    target := case when tg_op = 'DELETE' then old.dn_norm else new.dn_norm end;
    if target like '%,ou=changes,' || root then
        return coalesce(new, old);
    end if;
    env := coalesce(entry_area_env(target), '');
    need := required_approvals(env);
    if need <= 1 then
        return coalesce(new, old);
    end if;
    c := (select attrs from entry where dn_norm = 'cn=' || lower(chg) || ',ou=changes,' || root);
    have := cardinality(change_approvers(coalesce(c, '{}')));
    if have < need then
        raise exception 'opsdir: change % has % of the % approvals % needs (approvals-required): % more person(s) '
                        'approve it first', chg, have, need, coalesce(nullif(env, ''), 'the record'), need - have;
    end if;
    return coalesce(new, old);
end $$;

-- Named to fire before the grant guards (BEFORE triggers fire in name order), so a change short of approvals says so.
create trigger entry_validate_approvals_needed before insert or update on entry
    for each row execute function change_approvals_guard();
create trigger entry_guard_delete_approvals before delete on entry
    for each row execute function change_approvals_guard();

create or replace function grant_area_guard() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root text := (select min(dn_norm) from suffix);
    chg text := nullif(current_setting('opsdir.change_id', true), '');
    who text := requester();
    target text; attrs jsonb; env text; teams text[]; act text; c jsonb; approvers text[]; holding int; need int;
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
    c := coalesce((select e.attrs from entry e where e.dn_norm = 'cn=' || lower(chg) || ',ou=changes,' || root), '{}');
    approvers := change_approvers(c);
    holding := (select count(*) from unnest(approvers) a
                 where grant_holds(a, 'approve', env, teams, approver_teams(c, a)));
    need := greatest(required_approvals(env), 1);
    if holding < need then
        if need = 1 then
            raise exception 'opsdir: change % was approved by %, who may not approve %: no grant gives them approve '
                            'there', chg, coalesce(nullif(array_to_string(approvers, ', '), ''), 'nobody recorded'),
                target;
        end if;
        raise exception 'opsdir: change % has % approver(s) who may approve %, and % need to (approvals-required): '
                        'no grant gives the others approve there', chg, holding, target, need;
    end if;
    return coalesce(new, old);
end $$;
