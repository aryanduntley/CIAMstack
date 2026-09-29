# Amster export of the partner realm (synthetic)

A made-up PingAM configuration export (`amster export-config`) of Example Aero's `/partners` realm: one OAuth2 client, one journey with its nodes, one policy set and the OAuth2 provider settings. The demo reads it into the record with `opsdir import --change CHG-2004 pingam exports/amster`: the client becomes a standard integration, the journey and policies are held in the record, the provider settings are captured setting by setting, and the SMTP password is withheld.
