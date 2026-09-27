To: skyline-air <identity-ops@skyline-air.example>
Subject: Allowlist update needed before 2027-01-15 (Example Aero identity platform move)

Hello,

We are moving the Example Aero external identity platform to a new hosting environment. Planned cutover is 2027-01-15. Some addresses change (service names are still being confirmed).

Please add the following to the systems you operate:

- **Skyline Air IdP ingress allowlist (metadata and back-channel)**: add `203.0.113.200/32` (currently allowlisted: 203.0.113.10/32). Needed by 2026-11-17.

Please keep the existing entries until we confirm cutover; we'll tell you when they can go.

Thank you,
CIAM platform team

_Generated from the operations directory; entries skyline-air-ingress._
