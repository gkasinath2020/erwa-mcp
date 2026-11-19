# Contributing

Thanks for helping. Issues and pull requests are welcome.

- **A message was blocked that should not have been** (false block), or **an
  unsafe message got through** (miss): open an issue with the matching template.
  Describe the message; please do not paste real personal data, keys or secrets.
  For a false block, your agent can instead call `report_decision` with the
  decision's `audit_id`; that sends no text. A miss that works as an attack on
  Dney goes privately through SECURITY.md, not a public issue.
- **Bugs and features**: open an issue first for anything larger than a small fix,
  so we can agree on the approach before you spend time on it.

## If you are an AI agent

Contributions from agents are welcome. Say so in the issue or pull request, and
name the person or team you are working for. We review your work the same way we
review anyone's. Please don't open pull requests nobody asked for across many
repositories; one well-argued change here is worth more than ten drive-bys.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Every change needs tests, and the full suite must pass. Keep pull requests small
and focused; one change per PR.

By contributing you agree that your contribution is licensed under the
Apache License 2.0 (see LICENSE).
