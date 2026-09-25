-- opsdir reports: questions the directory answers directly in SQL.
set search_path = opsdir;

-- Everything that depends on an entry, transitively (reverse DN references).
-- "What breaks if this certificate expires / this attribute is removed / this server goes?"
create function dependents(target_dn text, max_depth int default 4)
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
create function owners_of(dns text[]) returns table (dn text, owner text) language sql stable as $$
    select e.dn, o.dn from entry e join entry_ref r on r.from_id = e.id and r.attr = 'ciamOwner'
      join entry o on o.id = r.to_id where e.dn = any (dns)
$$;

create view v_certificates as
select c.dn,
       a1(c.attrs, 'cn')                              as cert,
       a1(c.attrs, 'ciamCertPurpose')                 as purpose,
       gtime(a1(c.attrs, 'ciamNotAfter'))::date       as not_after,
       gtime(a1(c.attrs, 'ciamNotAfter'))::date - as_of() as days_left,
       array(select u.dn from entry_ref r join entry u on u.id = r.from_id
              where r.to_id = c.id and r.attr = 'ciamUsesCertificate') as used_by,
       aall(c.attrs, 'ciamSubjectAltName')            as names,
       a1(c.attrs, 'ciamKeyRole')                     as key_role
  from entry c where 'ciamCertificate' = any (c.object_classes);

-- Which consumers can read which privacy-classified attributes, through which ACI.
create view v_pii_exposure as
select a1(ua.attrs, 'ciamLdapName') as attribute,
       a1(ua.attrs, 'ciamPiiClass') as pii_class,
       a1(ua.attrs, 'ciamExportControlled') = 'TRUE' as export_controlled,
       a1(aci.attrs, 'cn')          as aci,
       a1(con.attrs, 'cn')          as consumer,
       a1(con.attrs, 'ciamBindDn')  as bind_dn,
       (select string_agg(a1(o.attrs, 'cn'), ',') from entry_ref r join entry o on o.id = r.to_id
         where r.from_id = con.id and r.attr = 'ciamOwner') as owner,
       a1(aci.attrs, 'ciamJustification') as justification
  from entry aci
  join entry_ref g on g.from_id = aci.id and g.attr = 'ciamAciGrantee'
  join entry con on con.id = g.to_id
  join entry ua on 'ciamUserAttribute' = any (ua.object_classes)
 where 'ciamAci' = any (aci.object_classes)
   and a1(ua.attrs, 'ciamPiiClass') in ('moderate', 'high')
   and a1(aci.attrs, 'ciamAciRight') is not null
   and exists (select 1 from jsonb_array_elements_text(aci.attrs -> 'ciamAciRight') x
                where x in ('read', 'all'))
   and (a1(aci.attrs, 'ciamAciAllAttributes') = 'TRUE'
        or exists (select 1 from entry_ref t where t.from_id = aci.id
                    and t.attr = 'ciamAciTargetAttr' and t.to_id = ua.id));

-- Effective last-change time of an entry: history after bootstrap, else the seeded ciamLastChanged.
create function last_changed(eid bigint) returns timestamptz language sql stable as $$
    select coalesce(
        (select max(h.at) from entry_history h join entry e on e.dn = h.dn
          where e.id = eid and h.change_id <> 'BOOTSTRAP'),
        (select gtime(a1(e.attrs, 'ciamLastChanged')) from entry e where e.id = eid))
$$;

-- Work instructions that depend on config changed after they were last validated.
create view v_stale_runbooks as
select a1(rb.attrs, 'cn') as runbook, a1(rb.attrs, 'ciamTitle') as title,
       gtime(a1(rb.attrs, 'ciamLastValidated'))::date as last_validated,
       t.dn as changed_dependency, last_changed(t.id)::date as changed_on
  from entry rb
  join entry_ref r on r.from_id = rb.id and r.attr = 'ciamAppliesTo'
  join entry t on t.id = r.to_id
 where 'ciamRunbook' = any (rb.object_classes)
   and last_changed(t.id) > gtime(a1(rb.attrs, 'ciamLastValidated'));

-- Consumers, ACIs and integrations nobody owns (or ACIs nobody justified).
create view v_unowned as
select e.dn, (select c from unnest(e.object_classes) c where c <> 'top' limit 1) as kind,
       concat_ws(', ', case when not e.attrs ? 'ciamOwner' then 'no owner' end,
                 case when 'ciamAci' = any (e.object_classes) and not e.attrs ? 'ciamJustification'
                      then 'no justification' end) as problem
  from entry e
 where (e.object_classes && array['ciamConsumer', 'ciamAci', 'ciamIntegration']
        and not e.attrs ? 'ciamOwner')
    or ('ciamAci' = any (e.object_classes) and not e.attrs ? 'ciamJustification');

-- Portability census: how much of the estate is environment-neutral.
create view v_portability as
select at.portability, count(*) as values
  from entry e, jsonb_each(e.attrs) j(k, vals), jsonb_array_elements(j.vals) v, attribute_type at
 where at.name = j.k group by 1 order by 2 desc;
