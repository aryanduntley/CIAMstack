-- Migration 0006: environment overrides of intent.
-- An environment may hold its own value for one attribute of a shared entry (a ciamOverride entry: ciamOverrides names
-- the entry, ciamOverrideAttribute the attribute, ciamOverrideValue the values). Only attributes whose definition says
-- X-OVERRIDABLE may be overridden (kept in attribute_type.rules with the value rules); the values must be valid for the
-- attribute (its value type, vocabulary, rules and SINGLE-VALUE), and the entry's classes must allow the attribute.
-- Chained into entry_problem after the secret guard and R1, so `upgrade` re-validates every stored override too.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

create function override_problem(p_dn text, p_classes text[], p_attrs jsonb) returns text language plpgsql stable as $$
declare
    attr text; target_dn text; at attribute_type; target entry; vals jsonb; v text;
begin
    if not ('ciamOverride' = any (p_classes)) then return null; end if;
    attr      := p_attrs -> 'ciamOverrideAttribute' ->> 0;
    target_dn := p_attrs -> 'ciamOverrides' ->> 0;
    vals      := p_attrs -> 'ciamOverrideValue';
    select * into at from attribute_type where lname = lower(attr);
    if not found then
        return format('opsdir: override "%s" names unknown attribute "%s"', p_dn, attr);
    end if;
    if not (at.rules ? 'X-OVERRIDABLE') then
        return format('opsdir: override "%s": "%s" may not be overridden per environment (its definition is not X-OVERRIDABLE)',
                      p_dn, at.name);
    end if;
    if at.single_value and jsonb_array_length(vals) > 1 then
        return format('opsdir: override "%s": "%s" is SINGLE-VALUE', p_dn, at.name);
    end if;
    for v in select jsonb_array_elements_text(vals) loop
        if at.value_type = 'vocab' then
            if not exists (select 1 from vocabulary w where w.attr = at.name and w.value = v) then
                return format('opsdir: override "%s": value "%s" for "%s" is not registered by any installed domain or adapter',
                              p_dn, v, at.name);
            end if;
        elsif not value_ok(at.value_type, v) then
            return format('opsdir: override "%s": value "%s" is not a valid %s for "%s"', p_dn, v, at.value_type, at.name);
        elsif not value_rules_ok(at.rules, v) then
            return format('opsdir: override "%s": value "%s" for "%s" breaks its rules %s', p_dn, v, at.name, at.rules);
        end if;
    end loop;
    -- the entry it overrides (R3 checks that it exists once the change is complete)
    select * into target from entry where dn_norm = norm_dn(target_dn);
    if found and not exists (select 1 from class_closure(target.object_classes) c
                              where at.name = any (c.must || c.may)) then
        return format('opsdir: override "%s": "%s" does not allow "%s" (classes %s)', p_dn, target.dn, at.name,
                      target.object_classes);
    end if;
    return null;
end $$;

alter function entry_problem(text, text[], jsonb) rename to entry_base_problem;

create function entry_problem(p_dn text, p_classes text[], p_attrs jsonb) returns text language plpgsql stable as $$
begin
    return coalesce(entry_base_problem(p_dn, p_classes, p_attrs), override_problem(p_dn, p_classes, p_attrs));
end $$;
