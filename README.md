# magento-stackgauge-signatures

A versioned, community-reviewable database of content signatures for detecting webshells and
Magecart-style skimmer injections on Magento stores - the "antivirus definitions" consumed by
[StackNuts StackGaugeSecurity](https://github.com/StackNuts/magento-stackgauge-security)'s
`ContentSignatureReporter`, and free for any other tool to use or fork.

MIT licensed, deliberately separate from StackGaugeSecurity's own license: signature *data*
benefits from the widest possible scrutiny and reuse, which is a different goal than the module
code itself has.

## Why a separate repo

A signature set is only as good as how many eyes have checked it for false positives and
gaps - keeping it in its own small, permissively-licensed repo makes that easy: anyone can
read, fork, or contribute to it without needing to touch (or license-agree to) the Magento
module at all. It also means new detections can ship the moment they're validated, independent
of the module's own release cycle.

## Format

```jsonc
{
  "version": "2026.10.0",
  "signatures": [
    {
      "id": "magecart-atob-eval",
      "name": "eval() of base64-decoded script content",
      "severity": "critical",
      "target": ["cms_content", "design_config"],
      "pattern_type": "literal",
      "pattern": "eval(atob(",
      "description": "...",
      "test_should_match": ["<script>eval(atob('...'))</script>"],
      "test_should_not_match": ["<script>var decoded = atob(x);</script>"]
    }
  ]
}
```

- `pattern_type` is `"literal"` (a plain substring check) or `"regex"` (a PHP-PCRE pattern with
  delimiters/flags, e.g. `"/pattern/i"`, `preg_match`-compatible). Prefer literal where a plain
  substring suffices.
- `target` is one or more of: `pub_php` (PHP files under `pub/media`/`pub/static`),
  `cms_content` (CMS block/page HTML), `design_config` (admin-editable HTML/JS config values).
  A consuming tool only needs to apply a signature to content of a type it declares a target
  for.
- `test_should_match` / `test_should_not_match` are required for every signature - they're
  enforced by the validation harness below, not just documentation.
- Keep `id` stable once published; bump the top-level `version` whenever the set changes.

## Validation

Every signature must pass `scripts/validate_signatures.php` before it can be merged - this runs
automatically on every push and pull request (see `.github/workflows/validate.yml`), and is the
same check `scripts/propose_signatures.php` applies to an AI-proposed candidate before it's
ever written to `signatures.json`.

It checks, per signature: required fields and allowed values, no duplicate `id`, a regex
pattern actually compiles, every `test_should_match` sample matches and every
`test_should_not_match` sample doesn't, and - independently of whichever samples the signature's
own author wrote - it matches *nothing* in `corpus/clean/`, a shared, hand-maintained set of
real-looking benign content (a legitimate analytics snippet, a consent banner, ordinary PHP
utility code). That last check matters most: a signature's own negative samples can't prove
anything about content its author never thought to try.

```bash
php scripts/validate_signatures.php
```

## Keeping the set current

`scripts/propose_signatures.php` asks Gemini (with Google Search grounding, on its free API
tier) to research current Magento/Adobe Commerce webshell and skimmer IoCs, then vets every
candidate through the exact same validator above before writing it. Nothing failing validation
is ever written, and nothing is ever auto-merged - `.github/workflows/propose-signatures.yml`
runs this daily and opens a pull request for human review, same as any other contribution.

To enable it on a fork:

```bash
gh secret set GEMINI_API_KEY --repo <you>/magento-stackgauge-signatures
gh api -X PUT repos/<you>/magento-stackgauge-signatures/actions/permissions/workflow \
  -F default_workflow_permissions=write -F can_approve_pull_request_reviews=true
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests adding or refining signatures are
welcome - include `test_should_match`/`test_should_not_match` samples and make sure
`validate_signatures.php` passes locally first.

## License

MIT - see [LICENSE](LICENSE).
