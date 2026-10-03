To: cloud-landing-zone <landing-zone@example-aero.test>
Subject: Landing zone changes needed for target/prod before 2027-01-15

Hello,

We are moving the Example Aero external identity platform to target/prod; planned cutover is 2027-01-15. Please set up the following in the landing zone you keep (the rendered terraform/landing-zone/ files hold what we can describe):

- A guardrail preventing `audit-log-disable` (as source/prod's `org-guardrails` does). Needed by 2027-01-15.
- A way for operators to come in by session (as source/prod's `operator-console`). Needed by 2027-01-15.

Thank you,
CIAM platform team

_Generated from the operations directory._
