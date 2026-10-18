-- Migration 0008: the record's identity (cn=record below the root, class ciamRecordIdentity; governance.identity).
-- Its org code and record ID are fixed once set and the entry can't be removed, whoever writes and under whichever
-- change. Once the record has an identity, a new change record under ou=changes must be named with its org code as
-- prefix (<org>-..., any case), so change names stay unique across companies; change records made before the identity
-- was set are left as they are. Runs after entry_validate (BEFORE triggers fire in name order), so dn_norm, rdn and
-- the canonical class names are set.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

create function record_identity_guard() returns trigger language plpgsql as $$
declare
    root text := (select min(dn_norm) from suffix);
    idn  text := 'cn=record,' || (select min(dn_norm) from suffix);
    org  text; rdn_val text;
begin
    if tg_op = 'DELETE' then
        if old.dn_norm = idn and 'ciamRecordIdentity' = any (old.object_classes) then
            raise exception 'opsdir: the record''s identity (%) can''t be removed', old.dn;
        end if;
        return old;
    end if;
    if tg_op = 'UPDATE' and old.dn_norm = idn and 'ciamRecordIdentity' = any (old.object_classes)
       and (not ('ciamRecordIdentity' = any (new.object_classes))
            or a1(new.attrs, 'ciamOrgCode') is distinct from a1(old.attrs, 'ciamOrgCode')
            or a1(new.attrs, 'ciamRecordId') is distinct from a1(old.attrs, 'ciamRecordId')) then
        raise exception 'opsdir: the record''s org code (%) and record ID are fixed once set',
            a1(old.attrs, 'ciamOrgCode');
    end if;
    if tg_op = 'INSERT' and 'ciamChange' = any (new.object_classes) and parent_dn(new.dn_norm) = 'ou=changes,' || root
    then
        select a1(attrs, 'ciamOrgCode') into org from entry
         where dn_norm = idn and 'ciamRecordIdentity' = any (object_classes);
        rdn_val := lower(substr(new.rdn, length(split_part(new.rdn, '=', 1)) + 2));
        if org is not null and left(rdn_val, length(org) + 1) <> org || '-' then
            raise exception 'opsdir: change record "%" isn''t named %-...: this record''s change records start with '
                            'its org code', new.dn, org;
        end if;
    end if;
    return new;
end $$;

create trigger entry_validate_record_identity before insert or update on entry
    for each row execute function record_identity_guard();
create trigger entry_guard_delete_record_identity before delete on entry
    for each row execute function record_identity_guard();
