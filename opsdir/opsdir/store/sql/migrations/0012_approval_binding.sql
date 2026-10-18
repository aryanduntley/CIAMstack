-- Migration 0012: an approval covers the change as it was approved.
-- Once a change record (ciamChange under ou=changes) is approved or applied, the records it proposes
-- (ciamChangeRecords, what `opsdir fix approved` applies) can't change: editing them is refused, so an approval can't
-- be reused for other records; a different proposal is a new change. Its title and the rest stay writable (change
-- records are mirrored from ITSM). Outside the initial load (BOOTSTRAP), whoever writes. Runs after change_approval
-- (BEFORE triggers fire in name order).
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

create function change_bound() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
declare
    root text := (select min(dn_norm) from suffix);
begin
    if current_setting('opsdir.change_id', true) = 'BOOTSTRAP' or not ('ciamChange' = any (new.object_classes))
       or parent_dn(new.dn_norm) is distinct from 'ou=changes,' || root
       or a1(old.attrs, 'ciamChangeStatus') not in ('approved', 'applied') then
        return new;
    end if;
    if old.attrs -> 'ciamChangeRecords' is distinct from new.attrs -> 'ciamChangeRecords' then
        raise exception 'opsdir: change % was % as it stood: the records it proposes can''t change after approval; '
                        'propose a new change', a1(new.attrs, 'cn'), a1(old.attrs, 'ciamChangeStatus');
    end if;
    return new;
end $$;

create trigger entry_validate_change_bound before update on entry
    for each row execute function change_bound();
