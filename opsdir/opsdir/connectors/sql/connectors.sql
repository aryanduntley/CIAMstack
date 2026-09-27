-- cross-domain views (connectors): entries nobody owns across directory and federation.
set search_path = opsdir;

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
