-- Migration 0005: the store refuses secret material (SPEC R4).
-- Secrets are referenced (ref-uri), never stored. The forms secret material takes are data: the core registers the
-- generic ones (private keys, credentials in URLs, tokens, secret assignments, stored LDAP passwords), each installed
-- adapter its vendor's; `opsdir upgrade` syncs this table. Every entry is checked on write, and on re-validation after
-- a new pattern is installed, before any other check, and the refusal never repeats the value. Applied once and
-- recorded with its checksum: never edit it; add a new migration instead.
set search_path = opsdir;

create table secret_pattern (
    name        text primary key,
    pattern     text not null,          -- a regular expression in the dialect Python and PostgreSQL share
    owner       text not null,          -- opsdir (the core) or the adapter that registers it
    description text not null
);

-- The secret material an entry would store, as a problem naming the attributes and patterns (never the values),
-- or null when there is none.
create function secret_problem(p_dn text, p_attrs jsonb) returns text language plpgsql stable as $$
declare hits text;
begin
    select string_agg(s.name, ', ' order by s.name) into hits from secret_pattern s where p_dn ~ s.pattern;
    if hits is not null then
        return format('opsdir: an entry name holds what looks like secret material (%s); opsdir stores references '
                      'to secrets, never secrets (SPEC R4)', hits);
    end if;
    select string_agg(h, ', ' order by h) into hits from (
        select distinct format('%s (%s)', a.key, s.name) h
          from jsonb_each(p_attrs) a
         cross join lateral jsonb_array_elements_text(
               case jsonb_typeof(a.value) when 'array' then a.value else '[]'::jsonb end) v(x)
          join secret_pattern s on v.x ~ s.pattern) found;
    if hits is not null then
        return format('opsdir: "%s" holds what looks like secret material in %s; opsdir stores references to '
                      'secrets, never secrets (SPEC R4)', p_dn, hits);
    end if;
    return null;
end $$;

-- R1 (0004's entry_problem, unchanged) runs after the secret check, so no other message can repeat a secret value.
alter function entry_problem(text, text[], jsonb) rename to entry_schema_problem;

create function entry_problem(p_dn text, p_classes text[], p_attrs jsonb) returns text language plpgsql stable as $$
begin
    return coalesce(secret_problem(p_dn, p_attrs), entry_schema_problem(p_dn, p_classes, p_attrs));
end $$;
