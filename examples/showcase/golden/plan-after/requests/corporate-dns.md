To: corporate-dns <dns@example-aero.test>
Subject: DNS changes needed for target/prod before 2027-01-15

Hello,

We are moving the Example Aero external identity platform to target/prod; planned cutover is 2027-01-15. Please set up the following in the DNS zones you run:

- In zone `example-aero.test`, point `apps.example-aero.test` to `198.51.100.79` at cutover (today `198.51.100.22`); before that, lower its TTL from 3600 s to 60 s by 2027-01-13. Needed by 2027-01-15.
- In zone `example-aero.test`, point `login.example-aero.test` to `198.51.100.78` at cutover (today `198.51.100.21`); before that, lower its TTL from 3600 s to 60 s by 2027-01-13. Needed by 2027-01-15.
- In zone `example-aero.test`, point `sso.example-aero.test` to `198.51.100.77` at cutover (today `198.51.100.20`); before that, lower its TTL from 3600 s to 60 s by 2027-01-13. Needed by 2027-01-15.

Thank you,
CIAM platform team

_Generated from the operations directory._
