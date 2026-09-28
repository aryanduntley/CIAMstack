-- Migration 0004: value rules and re-validation.
-- An attribute type may state rules beyond its value type (X-MIN, X-MAX, X-PATTERN, X-MAX-LENGTH; custom fields use
-- them). Schema checking (R1) moves into entry_problem(), which the write trigger calls and `upgrade` (or a change to
-- the schema's definitions) runs over every stored entry, so a definition that tightens can't leave invalid entries
-- behind. Messages are unchanged. Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

alter table attribute_type add column rules jsonb not null default '{}';

-- A value within the rules of its attribute type (rules: {"X-MIN": "7", "X-MAX": "90", "X-PATTERN": "^...$",
-- "X-MAX-LENGTH": "40"}); the value type itself is value_ok's.
create function value_rules_ok(rules jsonb, s text) returns boolean language plpgsql immutable as $$
begin
    if rules ? 'X-MIN' and s::numeric < (rules ->> 'X-MIN')::numeric then return false; end if;
    if rules ? 'X-MAX' and s::numeric > (rules ->> 'X-MAX')::numeric then return false; end if;
    if rules ? 'X-PATTERN' and s !~ (rules ->> 'X-PATTERN') then return false; end if;
    if rules ? 'X-MAX-LENGTH' and length(s) > (rules ->> 'X-MAX-LENGTH')::int then return false; end if;
    return true;
exception when others then return false;
end $$;

-- R1 for one entry: its classes, attributes, values and RDN against the registry. The problem, or null when valid.
create function entry_problem(p_dn text, p_classes text[], p_attrs jsonb) returns text language plpgsql stable as $$
declare
    k text; vals jsonb; v text; at attribute_type; allowed text[]; required text[]; nstruct int;
    rdn text; rdn_attr text; rdn_val text;
begin
    if exists (select 1 from unnest(p_classes) x where lower(x) not in (select lname from object_class)) then
        return format('opsdir: unknown object class in %s on "%s"', p_classes, p_dn);
    end if;
    select count(*) into nstruct from class_closure(p_classes) where kind = 'STRUCTURAL';
    if nstruct = 0 then return format('opsdir: "%s" has no structural object class', p_dn); end if;

    select coalesce(array_agg(distinct m), '{}') into required
      from class_closure(p_classes) c, unnest(c.must) m where m <> 'objectClass';
    select coalesce(array_agg(distinct a), '{}') into allowed
      from class_closure(p_classes) c, unnest(c.must || c.may) a;

    for k, vals in select * from jsonb_each(p_attrs) loop
        select * into at from attribute_type where name = k;
        if not found then return format('opsdir: unknown attribute "%s" on "%s"', k, p_dn); end if;
        if not (k = any (allowed)) then
            return format('opsdir: attribute "%s" not allowed by %s on "%s"', k, p_classes, p_dn);
        end if;
        if jsonb_typeof(vals) <> 'array' or jsonb_array_length(vals) = 0 then
            return format('opsdir: "%s" on "%s" must be a non-empty array', k, p_dn);
        end if;
        if at.single_value and jsonb_array_length(vals) > 1 then
            return format('opsdir: "%s" is SINGLE-VALUE on "%s"', k, p_dn);
        end if;
        for v in select jsonb_array_elements_text(vals) loop
            if at.value_type = 'vocab' then
                if not exists (select 1 from vocabulary w where w.attr = k and w.value = v) then
                    return format('opsdir: value "%s" for "%s" on "%s" is not registered by any installed domain or adapter (registered: %s)',
                        v, k, p_dn, coalesce((select string_agg(distinct w.value, ', ' order by w.value)
                                                from vocabulary w where w.attr = k), 'none'));
                end if;
            elsif not value_ok(at.value_type, v) then
                return format('opsdir: value "%s" is not a valid %s for "%s" on "%s"', v, at.value_type, k, p_dn);
            elsif not value_rules_ok(at.rules, v) then
                return format('opsdir: value "%s" for "%s" on "%s" breaks its rules %s', v, k, p_dn, at.rules);
            end if;
        end loop;
    end loop;

    select array_agg(r) into required from unnest(required) r where not p_attrs ? r;
    if required is not null then
        return format('opsdir: "%s" is missing required attribute(s) %s', p_dn, required);
    end if;

    rdn      := split_part(p_dn, ',', 1);
    rdn_attr := split_part(rdn, '=', 1);
    rdn_val  := substr(rdn, length(rdn_attr) + 2);
    select name into k from attribute_type where lname = lower(rdn_attr);
    if k is null or not exists (select 1 from jsonb_array_elements_text(p_attrs -> k) x
                                 where lower(x) = lower(rdn_val)) then
        return format('opsdir: RDN "%s" is not an attribute value of "%s"', rdn, p_dn);
    end if;
    return null;
end $$;

-- The write trigger: tree and governance (R2, R5) here, schema checking (R1) through entry_problem.
create or replace function entry_before_write() returns trigger language plpgsql as $$
declare problem text; pdn text;
begin
    new.dn_norm := norm_dn(new.dn);
    new.rdn     := split_part(new.dn, ',', 1);
    new.change_id := require_change(new.dn_norm);
    new.modified_at := now(); new.modified_by := current_user;

    -- parent must exist, unless this is a naming context
    pdn := parent_dn(new.dn_norm);
    if exists (select 1 from suffix where dn_norm = new.dn_norm) then
        new.parent_id := null;
    else
        select id into new.parent_id from entry where dn_norm = pdn;
        if new.parent_id is null then
            raise exception 'opsdir: parent entry "%" of "%" does not exist', pdn, new.dn;
        end if;
    end if;

    problem := entry_problem(new.dn, new.object_classes, new.attrs);
    if problem is not null then raise exception '%', problem; end if;
    -- canonical object class names
    new.object_classes := array(select oc.name from object_class oc
                                 where oc.lname = any (select lower(x) from unnest(new.object_classes) x));
    return new;
end $$;
