Thank you for contributing!

Guidelines

- Fork the repository and open a pull request against `main`.
- One signature (or a small, related group) per PR - keeps review focused.
- Every signature needs `test_should_match` and `test_should_not_match` samples - these are
  enforced by the validator, not optional documentation.
- Keep a regex specific and anchored to the actual artifact; avoid anything broad enough to
  risk matching legitimate analytics/consent/chat-widget scripts or ordinary PHP utility code.
  If you're not sure, add a sample of the kind of legitimate content you're worried about to
  `corpus/clean/` as part of your PR - that's the strongest way to prove a pattern is safe.
- Never include a real, functioning malicious payload as a test sample - a realistic but inert
  shape (see the existing samples in `signatures.json`) is enough to validate a pattern without
  publishing something someone could copy-paste and use.

Running the validator

```bash
php scripts/validate_signatures.php
```

This is the same check CI runs on every push and PR - if it passes locally, it'll pass there.

Reporting issues

- Open issues at: https://github.com/StackNuts/magento-stackgauge-signatures/issues
