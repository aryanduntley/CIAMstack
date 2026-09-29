# PingGateway configuration of the partner portal (synthetic)

A made-up PingGateway configuration: the gateway's own settings (`config/`) and the route that signs partner staff in with the PingAM partner realm before passing requests to the partner portal application. The demo reads it with `opsdir import --change CHG-2004 pinggateway exports/ig`: the route is linked to the `partner-portal` integration (imported from the Amster export) and to the realm's issuer; the application is another team's, reached at the same host from every environment, which the plan asks to confirm.
