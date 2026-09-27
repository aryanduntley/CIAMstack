To: supplier-portal-team <supplier-portal@example-aero.test>
Subject: Allowlist update needed before 2027-01-15 (Example Aero identity platform move)

Hello,

We are moving the Example Aero external identity platform to a new hosting environment. Planned cutover is 2027-01-15. Service names stay the same; some addresses change.

Please add the following to the systems you operate:

- **Supplier portal outbound security group (Terraform)**: add `10.60.1.100/32` (currently allowlisted: 10.20.1.100/32). Needed by 2026-12-27.

Please keep the existing entries until we confirm cutover; we'll tell you when they can go.

Thank you,
CIAM platform team

_Generated from the operations directory; entries supplier-portal-egress-sg._
