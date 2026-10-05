To: network-security <netsec@example-aero.test>
Subject: Network changes needed for target/prod before 2027-01-15

Hello,

We are moving the Example Aero external identity platform to target/prod; planned cutover is 2027-01-15. Please set up the following in the network you keep (where an item is rendered as Terraform, its root is named):

- Allow `email-smtp.us-east-1.amazonaws.com` (messaging) through `egress-firewall` (firewall) for target/prod: `pf-engine` reach it. Needed by 2027-01-15.
- Everything you keep for target/prod is rendered in `terraform/landing-zone/network-security/` (what already exists carries import blocks, so you can adopt it into your state). Needed by 2027-01-15.
- Route table `rt-private` for subnets `subnet-ds`, `subnet-pf`, `subnet-am`, `subnet-idm`, `subnet-ig`: 0.0.0.0/0 nat pf-egress: to set up (`terraform/landing-zone/network-security/network.tf`). Needed by 2027-01-15.
- Flow log `flow-vnet` (network) to `ops-logs`, kept 14 days: to set up (`terraform/landing-zone/network-security/network.tf`). Needed by 2027-01-15.

Thank you,
CIAM platform team

_Generated from the operations directory._
