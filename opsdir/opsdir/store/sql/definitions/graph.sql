-- opsdir graph and history functions over the store (technology-neutral), and the portability census.
-- A definition: holds no data and is re-applied on every migrate (views are dropped first, functions use
-- create or replace; a function whose signature changes is dropped by a migration).
set search_path = opsdir;

-- Everything that depends on an entry, transitively (reverse DN references).
-- "What breaks if this certificate expires / this attribute is removed / this server goes?"
create or replace function dependents(target_dn text, max_depth int default 4)
returns table (depth int, dn text, via_attr text, classes text[]) language sql stable as $$
    with recursive d(id, depth, via, path) as (
        select e.id, 0, null::text, array[e.id] from entry e where e.dn_norm = norm_dn(target_dn)
        union all
        select r.from_id, d.depth + 1, r.attr, d.path || r.from_id
          from d join entry_ref r on r.to_id = d.id
         where d.depth < max_depth and not r.from_id = any (d.path)
           and r.attr not in ('ciamChangeRef', 'ciamInvolved',        -- history, not dependency
                              'ciamRotationRunbook', 'ciamOwner')    -- pointers to docs / parties
    )
    select min(d.depth), e.dn, (array_agg(d.via order by d.depth))[1], e.object_classes
      from d join entry e on e.id = d.id where d.depth > 0
     group by e.dn, e.object_classes order by 1, 2
$$;

-- Owners reachable from a set of entries (forward ciamOwner edges).
create or replace function owners_of(dns text[]) returns table (dn text, owner text) language sql stable as $$
    select e.dn, o.dn from entry e join entry_ref r on r.from_id = e.id and r.attr = 'ciamOwner'
      join entry o on o.id = r.to_id where e.dn = any (dns)
$$;

-- Effective last-change time of an entry: history after bootstrap, else the seeded ciamLastChanged.
create or replace function last_changed(eid bigint) returns timestamptz language sql stable as $$
    select coalesce(
        (select max(h.at) from entry_history h join entry e on e.dn = h.dn
          where e.id = eid and h.change_id <> 'BOOTSTRAP'),
        (select gtime(a1(e.attrs, 'ciamLastChanged')) from entry e where e.id = eid))
$$;

-- Portability census: how much of the estate is environment-neutral.
create view v_portability as
select at.portability, count(*) as values
  from entry e, jsonb_each(e.attrs) j(k, vals), jsonb_array_elements(j.vals) v, attribute_type at
 where at.name = j.k group by 1 order by 2 desc;
