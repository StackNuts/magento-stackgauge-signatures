---
name: magento-rule-author
description: Writes detection signatures for compromised Magento stores from one source at a time (an OWASP CoreRuleSet rule file, or a Sansec/Sucuri/Malwarebytes write-up), checks them with this repo's validator, and proposes them as a pull request. Use when asked to add or refresh Magento malware signatures from a source.
---

# Magento rule author

Each run handles **one source**. You draft signatures from it, check them, and propose the ones that pass.

## Where rules go

There are two kinds, and they live in two files.

- **Core rules** (`signatures.json`): code-level detection. Webshell code, encoded payloads, backdoor markers, skimmer script logic, and specific parameter names or keys. These are what a scanner should run by default. Most rules should be core.
- **IOC rules** (`ioc/indicators.json`): domains and IP addresses. Set `"ioc": true` on the signature. They expire 180 days after they are added, and the validator reports expired entries. They are optional to run, because they go stale quickly.

Do not put IP addresses in core rules. Do not put a bare domain list in core rules unless it sits inside a code pattern, such as a script tag that loads from it.

## Ground rules

- **Only use strings that appear in the source.** Every literal, domain, IP or regex fragment must come from the text you were given. Do not invent indicators.
- **One technique per signature.** Group several hosts that belong to one campaign into one regex with alternation (`/\b(?:a\.com|b\.com)\b/i`), but never mix unrelated techniques.
- **Be specific.** A bare `eval(`, `base64_decode(` or `shell_exec(` matches ordinary code and is not a signature. Anchor on the combination the source shows.
- **No bare paths or file names as literals.** A literal such as `pub/media/custom_options/` or `health_check.php` matches any file that mentions it. The checker rejects these. Describe the code that touches the file instead.
- **Do not repeat an existing technique.** Check the checker's output for "same technique as existing signature". Hosts already covered by another rule should not be repeated.
- **Magento only.** Skip generic PHP rules that do not describe a Magento-relevant compromise, and say so in the report.
- **Attribution.** CoreRuleSet is Apache-2.0. Put the rule id and `CoreRuleSet (Apache-2.0)` in the signature's `description`, and the rule file URL in `source`.
- **Do not edit `signatures.json` or `ioc/indicators.json` by hand.** Use the checker with `--apply`.
- **At most five signatures per source.** Quality over quantity.

## Steps

1. **Get the source text.**
   - CoreRuleSet file: `php scripts/crs_rules.php <raw-url-of-conf>` lists each regex rule with its id, message and pattern.
   - Blog or research article: `php scripts/fetch_article.php <url> data/sources/<slug>.txt`, then read the code blocks at the top of that file.
2. **Choose what to draft.** Pick code a scanner could match inside a file or CMS block: webshell code, encoded payloads, skimmer script, backdoor markers. Skip anything that exists only in HTTP traffic, in the database, or on a server outside Magento. Skip a source entirely if it gives you nothing usable, and say why.
3. **Write the draft** to `data/drafts/<slug>.json`:
   ```json
   {"signatures": [{
     "id": "kebab-case-id",
     "name": "Short name",
     "severity": "critical|warning",
     "source": "https://...",
     "target": ["pub_php", "cms_content", "design_config", "generated_php"],
     "pattern_type": "literal|regex",
     "pattern": "...",
     "description": "What it detects, and why it is specific. For CoreRuleSet: rule id and Apache-2.0 notice.",
     "test_should_match": ["text that contains the pattern"],
     "test_should_not_match": ["benign text the pattern must not match"],
     "ioc": false
   }]}
   ```
   - `pattern_type: literal` is a plain substring. `regex` needs `/.../flags` delimiters.
   - `test_should_match` should be verbatim text from the source where possible. `test_should_not_match` should be realistic benign Magento code.
   - `target` says where the technique lives: `pub_php` for files under `pub/`, `cms_content` and `design_config` for database content, `generated_php` for `generated/code/`.
   - Set `"ioc": true` only for domain or IP rules.
4. **Check the draft:**
   ```
   php scripts/check_draft.php data/drafts/<slug>.json --source data/sources/<slug>.txt
   ```
   This runs the validator, the clean corpus, the duplicate and overlap checks, the path and file-name rules, and (with `--source`) confirms the rule matches the source text. For CoreRuleSet rules, `--source` is optional.
5. **Fix and re-check** rejected signatures, up to two attempts each. Drop anything that still fails. Do not weaken a rule just to pass the checks.
6. **Apply** the accepted signatures:
   ```
   php scripts/check_draft.php data/drafts/<slug>.json --source data/sources/<slug>.txt --apply
   php scripts/test_discover.php
   php scripts/validate_signatures.php
   ```
   Core rules go to `signatures.json`, and IOC rules go to `ioc/indicators.json` with an expiry date. `--apply` also rewrites `signatures.json.sha256`; the module refuses any feed whose checksum does not match.
7. **Propose a pull request** from a branch named `rules/<slug>`:
   ```
   git checkout -b rules/<slug>
   git add signatures.json signatures.json.sha256 ioc/indicators.json
   git commit -m "Add <n> signatures from <source name>"
   git push -u origin rules/<slug>
   gh pr create --base main --title "Signatures from <source name>" --body "<list of signatures, each with its source and what it detects>"
   ```
   If `gh` is not available, push the branch and report the branch name and a compare link.
8. **Report** what was accepted and what was rejected, with the reason for each rejection. Note any CoreRuleSet rules skipped as not Magento-relevant, and any IOC rules that will need renewing.

## Maintenance

- `php scripts/validate_signatures.php` reports IOC entries past their `expires_on` date. Re-check each one against its source before renewing, or remove it.
- Each core rule costs a scan a little time on every file. Keep the core set to rules that describe a technique, not a single campaign.

## Output

End each run with a short summary: the source, the accepted signature ids (core and IOC separately), the rejected ids with reasons, the PR link or branch name, and that no API spend was involved (the skill runs in your Claude session).
