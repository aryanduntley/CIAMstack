"""The opsdir HTTP API: the operations layer over HTTPS for people signed in at the estate's identity provider. A
bearer token (an OIDC access token) names a person by its issuer and subject; every call runs as that recorded person,
checked against the record's grants, through the one API login only the server holds (create_app; `opsdir-api`)."""
