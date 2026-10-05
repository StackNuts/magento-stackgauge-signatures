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
  "version": "2026.10.1",
  "signatures": [
    {
      "id": "magecart-atob-eval",
      "name": "eval() of base64-decoded script content",
      "severity": "critical",
      "source": "",
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

- `severity` is `"critical"` (a confirmed indicator of compromise) or `"warning"` (a heuristic that
  needs human review).
- `source` is the URL of the write-up the signature was drawn from. Leave it as an empty string
  (`""`) if there is no known origin. It is recommended, but not validated.
- `pattern_type` is `"literal"` (a plain substring check) or `"regex"` (a PHP-PCRE pattern with
  delimiters/flags, e.g. `"/pattern/i"`, `preg_match`-compatible). Prefer literal where a plain
  substring suffices.
- `target` is one or more of: `pub_php` (PHP files under `pub/media`/`pub/static`),
  `cms_content` (CMS block/page HTML), `design_config` (admin-editable HTML/JS config values),
  `generated_php` (PHP under `generated/code/`, e.g. interceptor classes a backdoor can rewrite).
  A consuming tool only needs to apply a signature to content of a type it declares a target
  for.
- `test_should_match` / `test_should_not_match` are required for every signature - they're
  enforced by the validation harness below, not just documentation.
- Keep `id` stable once published; bump the top-level `version` whenever the set changes.

## Validation

Every signature must pass `scripts/validate_signatures.php` before it can be merged - this runs
automatically on every push and pull request (see `.github/workflows/validate.yml`), and is the
same check applied before a hand-written signature is merged.

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

`scripts/discover.php` reads the Sansec research sitemap and the RSS feeds from Sucuri, Malwarebytes
and The Hacker News, keeps articles published since its last run, and extracts the indicator strings
found in each one (code blocks, base64 blobs, domains, IP addresses, PHP file names and suspicious
calls). It writes them to `data/candidates/` and the workflow opens a pull request listing them. The
script never writes signatures: a person writes each signature by hand from the candidates, with a
`source` link, and the validator checks it.

Each article is processed once. The state file on the `state` branch records what has been read, so
each run only handles new material. The workflow is `.github/workflows/discover.yml` and runs daily.

To enable it on a fork, allow Actions to create pull requests (Settings → Actions → General) and make
sure the workflow token can write to the repository, so the state branch can be saved. No API keys
are needed.
## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests adding or refining signatures are
welcome - include `test_should_match`/`test_should_not_match` samples and make sure
`validate_signatures.php` passes locally first.

## Origins

This project was inspired by [c0defusi0n/securityscanner-signatures](https://github.com/c0defusi0n/securityscanner-signatures),
which showed how a community-maintained, signature-based scanner database could be structured
and shared.

Every signature has a `source` field linking to the write-up it was drawn from. Signatures
without a known origin leave that field blank.

## License

MIT - see [LICENSE](LICENSE).
