To: mro-analytics-team <mro-analytics@example-aero.test>
Subject: Allowlist update needed before 2027-01-15 (Example Aero identity platform move)

Hello,

We are moving the Example Aero external identity platform to a new hosting environment. Planned cutover is 2027-01-15. Some addresses change (service names are still being confirmed).

Please add the following to the systems you operate:

- **MRO data-center egress firewall**: add `10.60.1.100/32` (currently allowlisted: 10.20.1.100/32). Needed by 2026-12-11.

Please keep the existing entries until we confirm cutover; we'll tell you when they can go.

Thank you,
CIAM platform team

_Generated from the operations directory; entries mro-dc-egress-to-ldaps._
