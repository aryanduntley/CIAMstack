-- governance domain: work instructions that went stale.
set search_path = opsdir;

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
