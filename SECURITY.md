# Security

Please report vulnerabilities privately, not in a public issue.

Use GitHub's **Report a vulnerability** button on this repository's Security tab
(private vulnerability reporting). Include what you found, how to reproduce it, and
what an attacker could do with it. Please do not include real API keys, tokens or
anyone's personal data in the report.

We will acknowledge the report, keep you informed, and credit you when the fix
ships, unless you ask us not to.

In scope: this MCP server (auth handling, key handling, anything that could expose
another organization's data or let a request skip a check), and any reproducible
way to get an unsafe message past Dney. A single message you think
was judged wrongly, with no way to repeat it, is a false block or a miss: the
issue templates cover those.
