-- directory domain: who can read privacy-classified user attributes.
set search_path = opsdir;

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
