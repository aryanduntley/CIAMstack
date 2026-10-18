-- Migration 0009: the history is append-only. Every write to an entry adds a row (entry_history, the write trigger);
-- nothing ever changes or removes one, whoever connects: an UPDATE or DELETE of a history row is refused (and the
-- runtime login can't TRUNCATE it either: store.roles). Only dropping the whole schema (`opsdir init`, which rebuilds
-- the record) removes history.
-- Applied once and recorded with its checksum: never edit it; add a new migration.
set search_path = opsdir;

create function history_append_only() returns trigger language plpgsql as $$
begin
    raise exception 'opsdir: the history is append-only: a history row can''t be changed or removed';
end $$;

create trigger entry_history_append_only before update or delete on entry_history
    for each row execute function history_append_only();
