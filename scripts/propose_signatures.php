<?php
/**
 * Proposes new detection signatures by asking Gemini (with Google Search grounding) to
 * research current Magento/Adobe Commerce webshell and Magecart-skimmer indicators of
 * compromise, then vets every candidate locally - via the exact same validateSignatureSet()
 * the CI gate uses - before it ever touches signatures.json. A candidate that fails any check
 * (doesn't compile, fails its own test samples, or false-positives against corpus/clean/) is
 * logged and dropped, never written.
 *
 * Deliberately does not call out to any third-party vulnerability feed - Gemini's own search
 * grounding does that research live, so this has one less moving part (and one less repo) to
 * maintain than a design relying on a separately-hosted feed.
 *
 * AI-authored detections are never auto-merged: the calling GitHub Actions workflow commits
 * accepted candidates to a branch and opens a pull request for human review, same as any other
 * contribution to this repo.
 *
 * Pure PHP + curl, no Composer dependencies.
 */

declare(strict_types=1);

require __DIR__ . '/lib/matching.php';

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

$model = getenv('GEMINI_MODEL') ?: 'gemini-2.5-flash';
$signaturesPath = getenv('SIG_PATH') ?: __DIR__ . '/../signatures.json';
$cleanCorpusDir = getenv('CLEAN_CORPUS_DIR') ?: __DIR__ . '/../corpus/clean';
$maxNew = (int)(getenv('MAX_NEW') ?: 5);
$prBodyPath = getenv('PR_BODY_PATH') ?: __DIR__ . '/../pr_body.md';

$apiKey = getenv('GEMINI_API_KEY');
if ($apiKey === false || $apiKey === '') {
    fwrite(STDERR, "GEMINI_API_KEY is not set.\n");
    exit(1);
}

$existingRaw = @file_get_contents($signaturesPath);
$existing = $existingRaw !== false ? json_decode($existingRaw, true) : null;
if (!is_array($existing) || !isset($existing['signatures']) || !is_array($existing['signatures'])) {
    fwrite(STDERR, "{$signaturesPath} is not valid JSON with a top-level \"signatures\" array\n");
    exit(1);
}

$existingIds = array_column($existing['signatures'], 'id');
$coveredSummary = implode(
    "\n",
    array_map(
        static fn (array $sig): string => "- {$sig['id']}: {$sig['name']}",
        $existing['signatures']
    )
);

$systemPrompt = <<<PROMPT
You are a defensive security engineer writing detection signatures for a Magento store scanner
that checks CMS block/page content, admin-editable HTML/JS config values, and PHP files under
pub/ for INDICATORS OF COMPROMISE. You are not assessing whether a Magento version is
vulnerable - you are detecting the traces an already-compromised store would contain: injected
card-skimmer JavaScript, PHP webshells, and other post-exploitation artifacts.

Rules:
1. Use your search tool to find concrete, publicly documented IoCs - vendor/Sansec-style
   write-ups often publish literal skimmer code fragments, webshell marker strings, or
   injected-script patterns tied to specific campaigns or vulnerabilities.
2. Only propose a signature when there is a concrete, content-matchable artifact. If you
   cannot find one, propose nothing - quality over quantity.
3. Do not re-propose a concept already covered by an existing signature:
{$coveredSummary}
4. Each pattern is either "literal" (a plain substring) or "regex" (a PHP-PCRE pattern with
   delimiters and flags, e.g. "/pattern/i", preg_match-compatible). Prefer literal when a
   plain substring is enough - it's cheaper and can't backtrack. Keep a regex specific and
   anchored to the artifact; avoid anything broad enough to match legitimate analytics/consent/
   chat-widget scripts or ordinary PHP utility code.
5. Every signature must include 1-3 "test_should_match" samples (realistic malicious content
   it must match) and 1-3 "test_should_not_match" samples (realistic benign content it must
   NOT match) - these are used to auto-validate your proposal, and a candidate that fails its
   own samples will be rejected.
6. "target" is a list of: "pub_php" (PHP files under pub/media or pub/static),
   "cms_content" (CMS block/page HTML), "design_config" (admin-editable HTML/JS config values).

Reply with ONLY a compact JSON object, no prose, no markdown fences:
{"signatures":[{"id":"short-stable-slug","name":"...","severity":"critical|warning",
"target":["cms_content"],"pattern_type":"literal|regex","pattern":"...","description":"...",
"test_should_match":["..."],"test_should_not_match":["..."]}]}
PROMPT;

$userPrompt = "Propose up to {$maxNew} new, high-confidence detection signatures for current "
    . "Magento/Adobe Commerce webshell and Magecart-skimmer indicators of compromise.";

$payload = [
    'system_instruction' => ['parts' => [['text' => $systemPrompt]]],
    'contents' => [['role' => 'user', 'parts' => [['text' => $userPrompt]]]],
    'tools' => [['google_search' => (object)[]]],
    'generationConfig' => ['temperature' => 0, 'maxOutputTokens' => 8192],
];

$url = GEMINI_API_BASE . "/{$model}:generateContent?key={$apiKey}";
$ch = curl_init($url);
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
    CURLOPT_POSTFIELDS => json_encode($payload),
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => 180,
]);
$body = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

if ($body === false) {
    // Network-level failure (DNS, timeout, connection refused) - transient, leave files
    // untouched rather than failing the workflow outright.
    fwrite(STDERR, "Request failed: {$curlError}\n");
    exit(0);
}

if ($httpCode >= 400) {
    // Auth/quota/config problems are not transient - fail loudly so they get noticed and fixed.
    fwrite(STDERR, "Gemini HTTP {$httpCode}: " . substr($body, 0, 600) . "\n");
    exit(in_array($httpCode, [400, 401, 403, 404, 429], true) ? 1 : 0);
}

$response = json_decode($body, true);
$text = '';
foreach ($response['candidates'][0]['content']['parts'] ?? [] as $part) {
    $text .= $part['text'] ?? '';
}

if (!preg_match('/\{.*\}/s', $text, $jsonMatch)) {
    fwrite(STDERR, "Could not locate a JSON object in the model's response.\n");
    exit(0);
}

$parsed = json_decode($jsonMatch[0], true);
$candidates = is_array($parsed['signatures'] ?? null) ? $parsed['signatures'] : [];

$cleanFiles = listFilesRecursively($cleanCorpusDir);
$accepted = [];
$rejected = [];

foreach (array_slice($candidates, 0, $maxNew) as $candidate) {
    $id = $candidate['id'] ?? '(no id)';

    if (in_array($id, $existingIds, true)) {
        $rejected[$id] = ['duplicate of an existing signature id'];
        continue;
    }

    $errors = validateSignatureSet([$candidate], $cleanFiles);
    if ($errors !== []) {
        $rejected[$id] = $errors;
        continue;
    }

    $accepted[] = $candidate;
    $existingIds[] = $id;
}

$prBody = "## Proposed detection signatures\n\n"
    . "Generated by `propose_signatures.php` (model: `{$model}`), auto-validated against "
    . "corpus/clean/ before being written here. **Review before merging.**\n\n";

if ($accepted !== []) {
    $prBody .= "### Accepted (" . count($accepted) . ")\n\n";
    foreach ($accepted as $signature) {
        $prBody .= "- **{$signature['id']}** ({$signature['severity']}): {$signature['description']}\n";
    }
}

if ($rejected !== []) {
    $prBody .= "\n### Rejected (" . count($rejected) . ")\n\n";
    foreach ($rejected as $id => $errors) {
        $prBody .= "- **{$id}**: " . implode('; ', $errors) . "\n";
    }
}

file_put_contents($prBodyPath, $prBody);

if ($accepted === []) {
    echo "No vetted signatures to propose.\n";
    exit(0);
}

$existing['signatures'] = [...$existing['signatures'], ...$accepted];
$existing['version'] = date('Y-m-d');

file_put_contents(
    $signaturesPath,
    json_encode($existing, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
);

echo 'Added ' . count($accepted) . " vetted signature(s); rejected " . count($rejected) . ".\n";
