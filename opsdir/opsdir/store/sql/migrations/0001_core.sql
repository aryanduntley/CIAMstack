-- Migration 0001: the opsdir core, the LDAP information model on Postgres.
-- Applied once and recorded with its checksum: never edit it after it has been applied anywhere;
-- change the store with a new numbered migration (see store/migrations.py).
--
--
-- What LDAP gives us (kept):   a DIT of entries named by DNs, object classes with MUST/MAY
--                              attributes, multi-valued attributes, schema-checked writes.
-- What Postgres adds:          enforced referential integrity for DN references, transactions
--                              across many entries, typed validation, full change history,
--                              and a rule that every write carries an approved change record.

create schema if not exists opsdir;
set search_path = opsdir;

-- ---------------------------------------------------------------- schema registry
create table attribute_type (
    name         text primary key,                 -- canonical case, e.g. ciamNotAfter
    lname        text generated always as (lower(name)) stored unique,
    oid          text not null unique,
    syntax_oid   text not null,
    equality     text,
    value_type   text not null,                    -- X-VALUE-TYPE
    portability  text not null check (portability in
                 ('intent','contract','binding','secret-ref','observed','meta')),  -- X-PORTABILITY
    single_value boolean not null default false,
    description  text,
    origin       text,
    check (portability <> 'secret-ref' or value_type = 'ref-uri')   -- a secret can only ever be a reference
);

create table object_class (
    name        text primary key,
    lname       text generated always as (lower(name)) stored unique,
    oid         text not null unique,
    sup         text references object_class(name),
    kind        text not null check (kind in ('ABSTRACT','STRUCTURAL','AUXILIARY')),
    must        text[] not null default '{}',
    may         text[] not null default '{}',
    description text,
    origin      text
);

create table suffix (dn_norm text primary key);    -- naming contexts (roots of the DIT)
create table ref_scheme (scheme text primary key); -- reference schemes the installed adapters own

-- ---------------------------------------------------------------- the directory
create table entry (
    id             bigserial primary key,
    dn             text not null,
    dn_norm        text not null unique,
    rdn            text not null,
    parent_id      bigint references entry(id) on delete restrict,   -- non-leaf entries can't be deleted (LDAP rule)
    object_classes text[] not null,
    attrs          jsonb not null default '{}',                      -- {"attr": ["v1","v2"]}
    created_at     timestamptz not null default now(),
    modified_at    timestamptz not null default now(),
    modified_by    text not null default current_user,
    change_id      text not null
);
create index entry_parent_idx on entry(parent_id);
create index entry_rev_dn_idx on entry (reverse(dn_norm) text_pattern_ops);  -- subtree search = suffix match
create index entry_oc_idx on entry using gin (object_classes);
create index entry_attrs_idx on entry using gin (attrs jsonb_path_ops);

-- Every DN-valued attribute is also an edge here, so a referenced entry can't be deleted
-- while something still points at it (e.g. a certificate still used by an integration).
create table entry_ref (
    from_id bigint not null references entry(id) on delete cascade,
    attr    text   not null references attribute_type(name),
    to_id   bigint not null references entry(id) on delete restrict,
    primary key (from_id, attr, to_id)
);
create index entry_ref_to_idx on entry_ref(to_id);

create table entry_history (
    id         bigserial primary key,
    dn         text not null,
    op         text not null,
    old_attrs  jsonb,
    new_attrs  jsonb,
    old_classes text[],
    new_classes text[],
    change_id  text not null,
    at         timestamptz not null default now(),
    db_user    text not null default current_user
);

-- ---------------------------------------------------------------- helpers
create function norm_dn(dn text) returns text language sql immutable as $$
    select lower(regexp_replace(trim(dn), '\s*([=,])\s*', '\1', 'g'))
$$;

create function parent_dn(dn text) returns text language sql immutable as $$
    select case when position(',' in dn) > 0 then substr(dn, position(',' in dn) + 1) end
$$;

create function as_of() returns date language sql stable as $$
    select coalesce(nullif(current_setting('opsdir.as_of', true), '')::date, current_date)
$$;

create function gtime(v text) returns timestamptz language sql immutable as $$
    select to_timestamp(left(v, 14), 'YYYYMMDDHH24MISS') at time zone 'UTC'
$$;

create function a1(attrs jsonb, name text) returns text language sql immutable as $$
    select attrs -> name ->> 0
$$;

create function aall(attrs jsonb, name text) returns text[] language sql immutable as $$
    select coalesce(array(select jsonb_array_elements_text(attrs -> name)), '{}')
$$;

-- Object-class closure: the classes plus all superclasses.
create function class_closure(classes text[]) returns setof object_class language sql stable as $$
    with recursive c as (
        select oc.* from object_class oc where oc.lname = any (select lower(x) from unnest(classes) x)
        union
        select p.* from object_class p join c on p.name = c.sup
    ) select * from c
$$;

create function value_ok(vt text, s text) returns boolean language plpgsql stable as $$
begin
    if vt in ('string') then return length(s) > 0;
    elsif vt = 'json' then perform s::jsonb; return true;
    elsif vt = 'int' then return s ~ '^-?[0-9]+$';
    elsif vt = 'port' then return s ~ '^[0-9]{1,5}$' and s::int between 1 and 65535;
    elsif vt = 'bool' then return s in ('TRUE','FALSE');
    elsif vt = 'time' then return s ~ '^[0-9]{14}Z$' and gtime(s) is not null;
    elsif vt = 'cidr' then perform s::cidr; return true;
    elsif vt = 'ip' then perform s::inet; return position('/' in s) = 0;
    elsif vt = 'fqdn' then return s ~* '^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$';
    elsif vt = 'url' then return s ~* '^(https?|ldaps?)://[^\s]+$';
    elsif vt = 'ref-uri' then return s ~ '^[a-z0-9-]+://[^\s]+$'
                                  and exists (select 1 from ref_scheme where scheme = split_part(s, '://', 1));
    elsif vt in ('dn','extdn') then return s ~ '^[^=,]+=[^,]+(,[^=,]+=[^,]+)*$';
    elsif vt like 'enum:%' then return s = any (string_to_array(substr(vt, 6), '|'));
    end if;
    return false;
exception when others then return false;
end $$;

-- ---------------------------------------------------------------- governance
-- Every write names a change (SET LOCAL opsdir.change_id). Outside the bootstrap load, that change
-- must exist under ou=changes with status approved/applied. Change records themselves are
-- writable with any change id (they are mirrored from ITSM).
create function require_change(target_dn_norm text) returns text language plpgsql as $$
declare chg text := nullif(current_setting('opsdir.change_id', true), '');
begin
    if chg is null then
        raise exception 'opsdir: every write needs a change id (SET LOCAL opsdir.change_id = ''CHG-…'')';
    end if;
    if chg <> 'BOOTSTRAP' and target_dn_norm not like '%,ou=changes,' || (select min(dn_norm) from suffix) then
        perform 1 from entry c
         where c.dn_norm = 'cn=' || lower(chg) || ',ou=changes,' || (select min(dn_norm) from suffix)
           and a1(c.attrs, 'ciamChangeStatus') in ('approved','applied');
        if not found then
            raise exception 'opsdir: change % is not an approved change record under ou=changes', chg;
        end if;
    end if;
    return chg;
end $$;

-- ---------------------------------------------------------------- entry validation (schema checking)
create function entry_before_write() returns trigger language plpgsql as $$
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
            if not value_ok(at.value_type, v) then
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

create trigger entry_validate before insert or update on entry
    for each row execute function entry_before_write();

create function entry_before_delete() returns trigger language plpgsql as $$
begin
    perform require_change(old.dn_norm);
    return old;
end $$;
create trigger entry_guard_delete before delete on entry
    for each row execute function entry_before_delete();

-- ---------------------------------------------------------------- DN references (deferred to commit)
-- Resolved at commit so a whole LDIF can be loaded in one transaction in any order.
create function entry_sync_refs() returns trigger language plpgsql as $$
declare e entry; r record; target bigint;
begin
    select * into e from entry where id = new.id;
    if not found then return null; end if;
    delete from entry_ref where from_id = e.id;
    for r in select k as attr, v from jsonb_each(e.attrs) as j(k, vals),
                    jsonb_array_elements_text(j.vals) v
              where k in (select name from attribute_type where value_type = 'dn') loop
        select id into target from entry where dn_norm = norm_dn(r.v);
        if target is null then
            raise exception 'opsdir: dangling reference on "%": % → "%"', e.dn, r.attr, r.v;
        end if;
        insert into entry_ref values (e.id, r.attr, target) on conflict do nothing;
    end loop;
    return null;
end $$;
create constraint trigger entry_refs after insert or update on entry
    deferrable initially deferred for each row execute function entry_sync_refs();

-- ---------------------------------------------------------------- history
create function entry_audit() returns trigger language plpgsql as $$
begin
    insert into entry_history (dn, op, old_attrs, new_attrs, old_classes, new_classes, change_id)
    values (coalesce(new.dn, old.dn), lower(tg_op),
            case when tg_op <> 'INSERT' then old.attrs end, case when tg_op <> 'DELETE' then new.attrs end,
            case when tg_op <> 'INSERT' then old.object_classes end, case when tg_op <> 'DELETE' then new.object_classes end,
            current_setting('opsdir.change_id', true));
    return null;
end $$;
create trigger entry_history after insert or update or delete on entry
    for each row execute function entry_audit();
