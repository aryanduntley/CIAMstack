To: network-security <netsec@example-aero.test>
Subject: Allowlist update needed before 2027-01-15 (Example Aero identity platform move)

Hello,

We are moving the Example Aero external identity platform to a new hosting environment. Planned cutover is 2027-01-15. Some addresses change (service names are still being confirmed).

Please add the following to the systems you operate:

- **HQ Panorama shared address group ciam-ldaps-servers (the corporate apps' egress to LDAPS)**: add `10.60.1.100/32` (currently allowlisted: 10.20.1.100/32). Needed by 2026-12-22.

Please keep the existing entries until we confirm cutover; we'll tell you when they can go.

Also, in the network you keep:

- Allow `email-smtp.us-east-1.amazonaws.com` (messaging) through `egress-firewall` (firewall) for target/prod: `pf-engine` reach it. Needed by 2027-01-15.
- Everything you keep for target/prod is rendered in `terraform/landing-zone/network-security/` (what already exists carries import blocks, so you can adopt it into your state). Needed by 2027-01-15.
- Route table `rt-private` for subnets `subnet-ds`, `subnet-pf`, `subnet-am`, `subnet-idm`, `subnet-ig`: 0.0.0.0/0 nat pf-egress: to set up (`terraform/landing-zone/network-security/network.tf`). Needed by 2027-01-15.
- Flow log `flow-vnet` (network) to `ops-logs`, kept 14 days: to set up (`terraform/landing-zone/network-security/network.tf`). Needed by 2027-01-15.

Thank you,
CIAM platform team

_Generated from the operations directory; entries hq-apps-egress-to-ldaps._
