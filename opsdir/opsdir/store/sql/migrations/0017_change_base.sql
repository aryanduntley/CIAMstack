-- Migration 0017: a proposed change applies only to what it was proposed against (governance; milestone 130). When a
-- change record proposes records (ciamChangeRecords: what a fix, an edit or an AI proposes) the store notes, for each
-- entry they touch, the last history row it had then (ciamChangeBase, '<normalized DN> <history id>', 0 when the
-- entry didn't exist), and sets it again whenever the proposed records change (the writer never sets it; a change
-- loaded under BOOTSTRAP gets none). Writing an entry under that change is then refused when another change wrote it
-- since: the people who approved the records saw the entry as it was, so the records are proposed again. A change
-- without a base (one proposing nothing, or proposed before this migration) is written as before. This holds for the
-- schema owner too: a stale proposal isn't a permission question, and break-glass work proposes a new change. Both
-- triggers run after entry_validate (BEFORE triggers fire in name order), which sets dn_norm.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

-- The last history row of the entry at a normalized DN (0: none).
create function last_history(p_dn text) returns bigint language sql stable set search_path = opsdir, pg_temp as $$
    select coalesce(max(id), 0) from entry_history where norm_dn(dn) = p_dn
$$;

-- What the records a change proposes were proposed against: '<normalized DN> <last history id>' per entry they touch.
-- The records are LDIF (folded lines unfolded first), as change_needs reads them (0015).
create function change_base(p_attrs jsonb) returns text[] language sql stable set search_path = opsdir, pg_temp as $$
    select coalesce(array_agg(t.dn || ' ' || last_history(t.dn) order by t.dn), '{}')
      from (select distinct norm_dn(btrim(m[1])) as dn
              from unnest(aall(p_attrs, 'ciamChangeRecords')) r,
                   lateral regexp_matches(replace(replace(r, E'\r\n', E'\n'), E'\n ', ''),
                                          '(?:^|\n)dn: *([^\n]*)', 'g') m) t
$$;

-- Fired before a change record is written: the store sets its base when its proposed records are new or changed, and
-- otherwise keeps the one it had, whatever the write says.
create function change_base_set() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root text := (select min(dn_norm) from suffix);
    base text[];
begin
    if not ('ciamChange' = any (new.object_classes))
       or parent_dn(new.dn_norm) is distinct from 'ou=changes,' || root then
        return new;
    end if;
    new.attrs := new.attrs - 'ciamChangeBase';
    if current_setting('opsdir.change_id', true) = 'BOOTSTRAP' then
        return new;
    end if;
    if tg_op = 'UPDATE' and old.attrs -> 'ciamChangeRecords' is not distinct from new.attrs -> 'ciamChangeRecords' then
        base := aall(old.attrs, 'ciamChangeBase');
    else
        base := change_base(new.attrs);
    end if;
    if cardinality(base) > 0 then
        new.attrs := jsonb_set(new.attrs, '{ciamChangeBase}', to_jsonb(base));
    end if;
    return new;
end $$;

create trigger entry_validate_change_base before insert or update on entry
    for each row execute function change_base_set();

-- Fired before every entry write under a change: an entry its base names may not have been written by another change
-- since the base was taken.
create function change_base_guard() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root text := (select min(dn_norm) from suffix);
    chg text := nullif(current_setting('opsdir.change_id', true), '');
    target text; base text; noted bigint; since_id bigint; since_change text;
begin
    if chg is null or chg = 'BOOTSTRAP' then
        return coalesce(new, old);
    end if;
    target := case when tg_op = 'DELETE' then old.dn_norm else new.dn_norm end;
    if target like '%,ou=changes,' || root then
        return coalesce(new, old);
    end if;
    select v into base
      from entry c, unnest(aall(c.attrs, 'ciamChangeBase')) v
     where c.dn_norm = norm_dn('cn=' || chg || ',ou=changes,' || root) and split_part(v, ' ', 1) = target
     limit 1;
    if base is null then
        return coalesce(new, old);
    end if;
    noted := split_part(base, ' ', 2)::bigint;
    select h.id, h.change_id into since_id, since_change from entry_history h
     where norm_dn(h.dn) = target and h.id > noted and h.change_id <> chg
     order by h.id desc limit 1;
    if since_id is not null then
        raise exception 'opsdir: % was written by change % after change % was proposed: its records were approved '
                        'against the entry as it was then; propose them again', target, since_change, chg;
    end if;
    return coalesce(new, old);
end $$;

create trigger entry_validate_change_base_guard before insert or update or delete on entry
    for each row execute function change_base_guard();
