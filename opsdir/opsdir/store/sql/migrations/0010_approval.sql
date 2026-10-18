-- Migration 0010: approval enforced by the store (governance.changes, governance.people).
-- (1) History records the login that wrote (session_user: SET ROLE can't change it).
-- (2) Only the schema owner writes under BOOTSTRAP, the initial load (`opsdir load` by the migration login acting as
--     the owner): every other login writes under an approved change, so BOOTSTRAP is no way around approval.
-- (3) A change record (ciamChange under ou=changes) written outside the initial load: the store sets its author
--     (ciamAuthor: the login that created it) and keeps it; it sets its approver (ciamApprovedBy: the login that
--     moved it to approved, or created it approved or applied) and keeps it; and it refuses
--       an approval by the change's own author, while the approval-separation setting isn't FALSE;
--       an approval by a login with no ciamPerson entry, once any person is recorded;
--       applied from anything but approved.
-- Runs after entry_validate (BEFORE triggers fire in name order), so dn_norm and the canonical class names are set.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

alter table entry_history alter column db_user set default session_user;

create function bootstrap_guard() returns trigger language plpgsql as $$
begin
    if current_setting('opsdir.change_id', true) = 'BOOTSTRAP'
       and not pg_has_role(current_user, (select nspowner from pg_namespace where nspname = 'opsdir'), 'USAGE') then
        raise exception 'opsdir: only the schema owner writes under BOOTSTRAP (the initial load); % writes under an '
                        'approved change', session_user;
    end if;
    return coalesce(new, old);
end $$;

create trigger entry_guard_bootstrap before insert or update or delete on entry
    for each row execute function bootstrap_guard();

create function change_approval() returns trigger language plpgsql as $$
declare
    root   text := (select min(dn_norm) from suffix);
    who    text := session_user;
    status text := a1(new.attrs, 'ciamChangeStatus');
    was    text;
    author text;
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
        new.attrs := jsonb_set(new.attrs, '{ciamApprovedBy}', jsonb_build_array(who));
    elsif tg_op = 'UPDATE' and old.attrs ? 'ciamApprovedBy' then
        new.attrs := jsonb_set(new.attrs, '{ciamApprovedBy}', old.attrs -> 'ciamApprovedBy');
    else
        new.attrs := new.attrs - 'ciamApprovedBy';
    end if;
    return new;
end $$;

create trigger entry_validate_change_approval before insert or update on entry
    for each row execute function change_approval();
