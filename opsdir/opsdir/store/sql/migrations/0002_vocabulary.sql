-- Migration 0002: values owned by the installed domains and adapters.
-- Attributes of value type `vocab` (cloud provider, provider partition, server and target roles) take only values
-- some installed domain or adapter declares; `opsdir upgrade` syncs this table from the registry. The core names
-- none of them. Applied once and recorded with its checksum: never edit it; add a new migration instead.
set search_path = opsdir;

create table vocabulary (
    attr  text not null references attribute_type(name),
    value text not null,
    owner text not null,                    -- the domain or adapter that declares it
    primary key (attr, value, owner)
);

-- Entry validation (R1/R2) as in 0001, plus: a `vocab` value must be registered.
create or replace function entry_before_write() returns trigger language plpgsql as $$
declare
    k text; vals jsonb; v text; at attribute_type; allowed text[]; required text[]; nstruct int;
    rdn_attr text; rdn_val text; pdn text;
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

    -- object classes: known, at least one structural; canonicalize names
    if exists (select 1 from unnest(new.object_classes) x
                where lower(x) not in (select lname from object_class)) then
        raise exception 'opsdir: unknown object class in % on "%"', new.object_classes, new.dn;
    end if;
    new.object_classes := array(select oc.name from object_class oc
                                 where oc.lname = any (select lower(x) from unnest(new.object_classes) x));
    select count(*) into nstruct from class_closure(new.object_classes) where kind = 'STRUCTURAL';
    if nstruct = 0 then raise exception 'opsdir: "%" has no structural object class', new.dn; end if;

    select coalesce(array_agg(distinct m), '{}') into required
      from class_closure(new.object_classes) c, unnest(c.must) m where m <> 'objectClass';
    select coalesce(array_agg(distinct a), '{}') into allowed
      from class_closure(new.object_classes) c, unnest(c.must || c.may) a;

    -- attributes: allowed by the classes, typed, single-valued where declared
    for k, vals in select * from jsonb_each(new.attrs) loop
        select * into at from attribute_type where name = k;
        if not found then raise exception 'opsdir: unknown attribute "%" on "%"', k, new.dn; end if;
        if not (k = any (allowed)) then
            raise exception 'opsdir: attribute "%" not allowed by % on "%"', k, new.object_classes, new.dn;
        end if;
        if jsonb_typeof(vals) <> 'array' or jsonb_array_length(vals) = 0 then
            raise exception 'opsdir: "%" on "%" must be a non-empty array', k, new.dn;
        end if;
        if at.single_value and jsonb_array_length(vals) > 1 then
            raise exception 'opsdir: "%" is SINGLE-VALUE on "%"', k, new.dn;
        end if;
        for v in select jsonb_array_elements_text(vals) loop
            if at.value_type = 'vocab' then
                if not exists (select 1 from vocabulary w where w.attr = k and w.value = v) then
                    raise exception 'opsdir: value "%" for "%" on "%" is not registered by any installed domain or adapter (registered: %)',
                        v, k, new.dn, coalesce((select string_agg(distinct w.value, ', ' order by w.value)
                                                  from vocabulary w where w.attr = k), 'none');
                end if;
            elsif not value_ok(at.value_type, v) then
                raise exception 'opsdir: value "%" is not a valid % for "%" on "%"', v, at.value_type, k, new.dn;
            end if;
        end loop;
    end loop;

    select array_agg(r) into required from unnest(required) r where not new.attrs ? r;
    if required is not null then
        raise exception 'opsdir: "%" is missing required attribute(s) %', new.dn, required;
    end if;

    -- the RDN value must be present in the entry (LDAP rule)
    rdn_attr := split_part(new.rdn, '=', 1);
    rdn_val  := substr(new.rdn, length(rdn_attr) + 2);
    select name into k from attribute_type where lname = lower(rdn_attr);
    if k is null or not exists (select 1 from jsonb_array_elements_text(new.attrs -> k) x
                                 where lower(x) = lower(rdn_val)) then
        raise exception 'opsdir: RDN "%" is not an attribute value of "%"', new.rdn, new.dn;
    end if;
    return new;
end $$;
