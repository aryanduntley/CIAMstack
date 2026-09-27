-- pki domain: certificate views.
set search_path = opsdir;

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
