-- Migration 0016: history rows come only from entry writes (governance; milestone 130). A history row is written by
-- the store when an entry is written (entry_audit, the write trigger), and by nothing else: entry_audit now runs with
-- its owner's rights (security definer), so the runtime login no longer needs, and no longer holds, the right to add
-- history rows itself (store.roles revokes it); and a row added any other way, by any login, the owner included, is
-- refused. The store sets who and when on every row itself (the requester, its API client and mapped teams, the
-- transaction's time), whatever the statement says. Together with 0009 (no row is ever changed or removed), the
-- history holds exactly what the writes made, whoever connects.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

alter function entry_audit() security definer set search_path = opsdir, pg_temp;

-- Fired before each history row is added: entry_audit's insert runs inside the entry write's trigger, so it is at
-- trigger depth 2 or more; a statement adding a row itself is at depth 1.
create function history_from_writes() returns trigger language plpgsql set search_path = opsdir, pg_temp as $$
begin
    if pg_trigger_depth() < 2 then
        raise exception 'opsdir: history rows are written only by the store, when an entry is written';
    end if;
    new.at := now();
    new.db_user := requester();
    new.client := requester_client();
    new.teams := requester_teams();
    return new;
end $$;

create trigger entry_history_from_writes before insert on entry_history
    for each row execute function history_from_writes();
