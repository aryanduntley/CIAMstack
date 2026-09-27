-- Migration 0003: a migration workspace remembers the live snapshot it was copied from.
-- The table has at most one row, and only in a workspace database. The workspace's changes are measured against
-- base_ldif; fingerprint tells whether the live record has changed since. Never edit this migration once applied.
set search_path = opsdir;

create table workspace_base (
    id          int primary key default 1 check (id = 1),
    source      text not null,                  -- the live database it was copied from (password removed)
    created_at  timestamptz not null default now(),
    fingerprint text not null,                  -- SHA-256 of base_ldif
    base_ldif   text not null                   -- the live directory exported when the workspace was created
);
