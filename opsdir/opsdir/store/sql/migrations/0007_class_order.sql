-- Migration 0007: object classes keep the order an entry was written with.
-- entry_before_write canonicalized class names by selecting them from object_class without an order, so the stored
-- order followed the table's physical row order (it changes as the registry is synced) instead of the entry's: an
-- export could differ from the entry as loaded. Names are still made canonical; the order is now the writer's.
-- Entries already stored keep their order until they are next written.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

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
    -- canonical object class names, in the order the entry gives them
    new.object_classes := array(select oc.name from unnest(new.object_classes) with ordinality as given(name, n)
                                 join object_class oc on oc.lname = lower(given.name) order by given.n);
    return new;
end $$;
