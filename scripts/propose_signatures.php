<?php
/**
 * Proposes new detection signatures. Tavily search supplies current write-ups on Magento/Adobe
 * Commerce webshell and Magecart-skimmer indicators of compromise; Cloudflare Workers AI turns
 * those snippets into candidate signatures. Every candidate is then vetted locally - via the
 * exact same validateSignatureSet() the CI gate uses - before it ever touches signatures.json.
 * A candidate that fails any check (doesn't compile, fails its own test samples, or
 * false-positives against corpus/clean/) is logged and dropped, never written.
 *
 * AI-authored detections are never auto-merged: the calling GitHub Actions workflow commits
 * accepted candidates to a branch and opens a pull request for human review, same as any other
 * contribution to this repo.
 *
 * Pure PHP + curl, no Composer dependencies. The network calls and the vetting/file-writing
 * logic are split into separate functions (searchTavily() / callWorkersAI() vs.
 * applyCandidates()) so the latter can be exercised with canned input and no network access
 * or API keys at all.
 */

declare(strict_types=1);

require __DIR__ . '/lib/matching.php';

const TAVILY_SEARCH_URL = 'https://api.tavily.com/search';

/**
 * Open-ended research queries, run every day. They are built from recurring themes in recent
 * Sansec and Sucuri write-ups (campaign-level reporting, skimmers, persistence, plugin backdoors)
 * rather than from specific CVE numbers or years, so they keep finding new material as it appears.
 *
 * @var list<string>
 */
const RESEARCH_QUERIES = [
    'Magento Adobe Commerce new malware campaign indicators of compromise',
    'Magecart skimmer new technique Magento checkout',
    'Adobe Commerce backdoor exploited in the wild stores compromised',
    'Magento webshell pub/media PHP indicators of compromise',
    'Magento backdoored extension plugin malicious code',
    'Magento skimmer Google Tag Manager or disguised image tag',
    'site:sansec.io magento research',
    'site:blog.sucuri.net magento malware',
];

/**
 * Sources the search is limited to. Without this, general news and job-board pages crowd out
 * the threat research (see the Tealium and job-listing hits from an unfiltered run). Add a domain
 * here only if it publishes Magento-specific indicators.
 *
 * @var list<string>
 */
const RESEARCH_DOMAINS = [
    'sansec.io',
    'blog.sucuri.net',
    'securityaffairs.com',
    'thehackernews.com',
    'securityweek.com',
    'bleepingcomputer.com',
    'malwarebytes.com',
    'akamai.com',
    'sourcedefense.com',
    'silentpush.com',
    'rfxn.com',
    'mirasvit.com',
    'mgt-commerce.com',
];

const TAVILY_MAX_RESULTS = 5;
const BRAVE_SEARCH_URL = 'https://api.search.brave.com/res/v1/web/search';
const BRAVE_MAX_RESULTS = 8;
const SNIPPET_CHARS = 1500;
const PAGE_CHARS = 6000;
const CONTEXT_CHARS = 40000;
const FETCH_SUCCESSES = 5;
const FETCH_ATTEMPTS = 10;
const TRIAGE_MODEL = '@cf/google/gemma-4-26b-a4b-it';
const TRIAGE_SNIPPET_CHARS = 200;
const TRIAGE_MAX_PICKS = 5;
const TRIAGE_MAX_TOKENS = 6000;

/**
 * Runs one Tavily search.
 *
 * @return array{ok: bool, fatal: bool, results: list<array{url: string, title: string, content: string}>, error: string}
 */
function searchTavily(string $apiKey, string $query): array
{
    $payload = [
        'query' => $query,
        'max_results' => TAVILY_MAX_RESULTS,
        'search_depth' => 'basic',
        'include_domains' => RESEARCH_DOMAINS,
    ];

    $ch = curl_init(TAVILY_SEARCH_URL);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', "Authorization: Bearer {$apiKey}"],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 60,
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'fatal' => false, 'results' => [], 'error' => "Tavily request failed: {$curlError}"];
    }

    if ($httpCode >= 400) {
        $fatal = in_array($httpCode, [400, 401, 403, 432, 433], true);
        return [
            'ok' => false,
            'fatal' => $fatal,
            'results' => [],
            'error' => "Tavily HTTP {$httpCode}: " . substr($body, 0, 300),
        ];
    }

    $response = json_decode($body, true);
    $results = [];
    foreach ($response['results'] ?? [] as $hit) {
        $results[] = [
            'url' => (string)($hit['url'] ?? ''),
            'title' => (string)($hit['title'] ?? ''),
            'content' => mb_substr((string)($hit['content'] ?? ''), 0, SNIPPET_CHARS),
        ];
    }

    return ['ok' => true, 'fatal' => false, 'results' => $results, 'error' => ''];
}

/**
 * Runs one Brave web search, limited to RESEARCH_DOMAINS via site: operators.
 *
 * @return array{ok: bool, fatal: bool, results: list<array{url: string, title: string, content: string}>, error: string}
 */
function searchBrave(string $apiKey, string $query): array
{
    $sites = implode(' OR ', array_map(static fn (string $d): string => "site:{$d}", RESEARCH_DOMAINS));
    $url = BRAVE_SEARCH_URL . '?count=' . BRAVE_MAX_RESULTS . '&q=' . rawurlencode("{$query} ({$sites})");

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Accept: application/json', "X-Subscription-Token: {$apiKey}"],
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 60,
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'fatal' => false, 'results' => [], 'error' => "Brave request failed: {$curlError}"];
    }

    if ($httpCode >= 400) {
        // A bad or unauthorised key is fatal; rate limits and server errors only skip this query.
        return [
            'ok' => false,
            'fatal' => in_array($httpCode, [401, 403], true),
            'results' => [],
            'error' => "Brave HTTP {$httpCode}: " . substr($body, 0, 300),
        ];
    }

    $response = json_decode($body, true);
    $results = [];
    foreach ($response['web']['results'] ?? [] as $hit) {
        // Brave's description is short, so the extra snippets are appended to give the model more text.
        $snippets = array_map(static fn ($s): string => strip_tags((string)$s), $hit['extra_snippets'] ?? []);
        $text = trim(strip_tags((string)($hit['description'] ?? '')) . "\n" . implode("\n", $snippets));
        $results[] = [
            'url' => (string)($hit['url'] ?? ''),
            'title' => (string)($hit['title'] ?? ''),
            'content' => mb_substr($text, 0, SNIPPET_CHARS),
        ];
    }

    return ['ok' => true, 'fatal' => false, 'results' => $results, 'error' => ''];
}

/**
 * Downloads a page's HTML. Returns null on any failure, so the caller can fall back to the
 * search snippet.
 */
function fetchPage(string $url): ?string
{
    if (!preg_match('#^https?://#i', $url)) {
        return null;
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_USERAGENT => 'Mozilla/5.0',
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 20,
        CURLOPT_MAXFILESIZE => 2000000,
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentType = (string)curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
    curl_close($ch);

    if ($body === false || $httpCode >= 400 || !str_contains($contentType, 'html')) {
        return null;
    }

    return $body;
}

/**
 * Turns a page into text for the model. Code blocks come first, since they hold the literal
 * skimmer and webshell strings that signatures are built from; the article text follows. The
 * result is capped at PAGE_CHARS.
 */
function extractPageText(string $html): string
{
    $html = mb_scrub($html, 'UTF-8');

    $codeBlocks = [];
    if (preg_match_all('#<(pre|code)\b[^>]*>(.*?)</\1>#is', $html, $matches)) {
        foreach ($matches[2] as $block) {
            $text = trim(html_entity_decode(strip_tags($block), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            if (mb_strlen($text) >= 20) {
                $codeBlocks[] = $text;
            }
        }
    }

    $body = preg_replace('#<(script|style|noscript|svg)\b[^>]*>.*?</\1>#is', ' ', $html);
    $articleText = trim(preg_replace('/\s+/', ' ', html_entity_decode(strip_tags((string)$body), ENT_QUOTES | ENT_HTML5, 'UTF-8')));

    $combined = $codeBlocks === []
        ? $articleText
        : "CODE BLOCKS:\n" . implode("\n---\n", $codeBlocks) . "\n\nARTICLE TEXT:\n" . $articleText;

    return mb_substr($combined, 0, PAGE_CHARS);
}

/**
 * Picks the sources that go into the prompt: fetched pages first, then snippets, within a total
 * character budget so the prompt stays a manageable size.
 *
 * @param array<string, array{url: string, title: string, content: string, fetched?: bool}> $sources
 * @return list<array{url: string, title: string, content: string}>
 */
function selectSourcesForPrompt(array $sources): array
{
    $ordered = array_values($sources);
    usort($ordered, static fn (array $a, array $b): int => ($b['fetched'] ?? false) <=> ($a['fetched'] ?? false));

    $selected = [];
    $used = 0;
    foreach ($ordered as $hit) {
        $room = CONTEXT_CHARS - $used;
        if ($room <= 500) {
            break;
        }
        $hit['content'] = mb_substr($hit['content'], 0, $room);
        $used += mb_strlen($hit['content']);
        $selected[] = ['url' => $hit['url'], 'title' => $hit['title'], 'content' => $hit['content']];
    }

    return $selected;
}

/**
 * Asks a small, cheap model which sources are worth reading in full. Returns the picked URLs
 * (empty on any failure, which leaves the original order in place) and the neurons it used.
 *
 * @param array<string, array{url: string, title: string, content: string}> $sources Keyed by URL.
 * @return array{urls: list<string>, neurons: float, error: string, raw: string}
 */
function triageSources(array $sources, string $apiToken, string $accountId): array
{
    $lines = [];
    foreach (array_values($sources) as $i => $hit) {
        $snippet = mb_substr(str_replace("\n", ' ', $hit['content']), 0, TRIAGE_SNIPPET_CHARS);
        $lines[] = ($i + 1) . ". {$hit['url']} - {$hit['title']}: {$snippet}";
    }

    $system = 'You triage search results for a researcher writing Magento malware detection signatures. '
        . 'Pick up to ' . TRIAGE_MAX_PICKS . ' URLs whose snippet describes concrete indicators (code, domains, '
        . 'file paths, IP addresses, payload strings) worth reading in full. Ignore stock news, job adverts, '
        . 'product marketing and general advice. Reply with ONLY JSON: {"read": ["url", ...]}';
    $user = "Results:\n" . implode("\n", $lines);

    $result = callWorkersAI($apiToken, $accountId, TRIAGE_MODEL, $system, $user, TRIAGE_MAX_TOKENS);
    $neurons = (float)($result['neurons'] ?? 0);
    if (!$result['ok']) {
        return ['urls' => [], 'neurons' => $neurons, 'error' => $result['error'], 'raw' => ''];
    }

    $picked = [];
    if (preg_match('/\{.*\}/s', $result['text'], $jsonMatch)) {
        $parsed = json_decode($jsonMatch[0], true);
        foreach ($parsed['read'] ?? [] as $url) {
            if (is_string($url) && isset($sources[$url]) && !in_array($url, $picked, true)) {
                $picked[] = $url;
            }
        }
    }

    return [
        'urls' => array_slice($picked, 0, TRIAGE_MAX_PICKS),
        'neurons' => $neurons,
        'error' => $picked === [] ? 'no usable URLs in the reply (finish: ' . ($result['finish'] ?? '?') . ')' : '',
        'raw' => $result['text'],
    ];
}

/**
 * Moves the triaged URLs to the front, in the order triage gave them. Everything else keeps its
 * original order behind them.
 *
 * @param array<string, array{url: string, title: string, content: string}> $sources
 * @param list<string> $urls
 * @return array<string, array{url: string, title: string, content: string}>
 */
function orderByPriority(array $sources, array $urls): array
{
    $ordered = [];
    foreach ($urls as $url) {
        $ordered[$url] = $sources[$url];
    }
    foreach ($sources as $url => $hit) {
        if (!isset($ordered[$url])) {
            $ordered[$url] = $hit;
        }
    }

    return $ordered;
}
/**
 * Formats search hits as a numbered source list for the model prompt.
 *
 * @param list<array{url: string, title: string, content: string}> $results
 */
function formatSources(array $results): string
{
    $lines = [];
    foreach ($results as $i => $hit) {
        $n = $i + 1;
        $lines[] = "[{$n}] {$hit['title']} ({$hit['url']})\n{$hit['content']}";
    }

    return implode("\n\n", $lines);
}

/**
 * Calls a Cloudflare Workers AI text-generation model via the native run endpoint.
 *
 * @return array{ok: bool, fatal: bool, text: string, error: string}
 */
function callWorkersAI(string $apiToken, string $accountId, string $model, string $systemPrompt, string $userPrompt, int $maxTokens = 4096): array
{
    $payload = [
        'messages' => [
            ['role' => 'system', 'content' => $systemPrompt],
            ['role' => 'user', 'content' => $userPrompt],
        ],
        'temperature' => 0,
        'max_tokens' => $maxTokens,
    ];

    $url = "https://api.cloudflare.com/client/v4/accounts/{$accountId}/ai/run/{$model}";
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', "Authorization: Bearer {$apiToken}"],
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 180,
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($body === false) {
        return ['ok' => false, 'fatal' => false, 'text' => '', 'error' => "Request failed: {$curlError}"];
    }

    if ($httpCode >= 400) {
        // Auth, quota and model-availability problems are not transient - fail loudly.
        $fatal = in_array($httpCode, [400, 401, 403, 404, 410], true);
        return [
            'ok' => false,
            'fatal' => $fatal,
            'text' => '',
            'error' => "Workers AI HTTP {$httpCode}: " . substr($body, 0, 600),
        ];
    }

    $response = json_decode($body, true);
    $text = (string)($response['result']['choices'][0]['message']['content'] ?? '');

    return [
        'ok' => true,
        'fatal' => false,
        'text' => $text,
        'error' => '',
        'neurons' => (float)($response['result']['usage']['neurons'] ?? 0),
        'finish' => (string)($response['result']['choices'][0]['finish_reason'] ?? ''),
    ];
}

/**
 * Extracts the first {...} JSON object from $text, tolerating surrounding prose or code fences.
 *
 * @return list<array<string, mixed>> The "signatures" array within it, or [] if none found.
 */
function extractCandidates(string $text): array
{
    if (!preg_match('/\{.*\}/s', $text, $jsonMatch)) {
        return [];
    }

    $parsed = json_decode($jsonMatch[0], true);
    if ($parsed === null) {
        // Models often write regex escapes such as \. straight into JSON, which is not a legal
        // escape. Double any backslash that does not start a legal escape, then try again.
        $backslash = chr(92);
        $repaired = preg_replace_callback(
            '/' . preg_quote($backslash, '/') . '(?![' . preg_quote($backslash, '/') . '"\/bfnrtu])/',
            static fn (): string => $backslash . $backslash,
            $jsonMatch[0]
        );
        $parsed = json_decode($repaired ?? '', true);
    }

    return is_array($parsed['signatures'] ?? null) ? $parsed['signatures'] : [];
}

/**
 * Lowercases and collapses whitespace, so grounding checks ignore line breaks and indentation.
 */
function normalizeForMatch(string $text): string
{
    return mb_strtolower(preg_replace('/\s+/', ' ', $text) ?? $text);
}

/**
 * Returns the longest run of literal characters in a regex. That run has to appear in a source
 * for the regex to be grounded in published content.
 */
function longestRegexLiteral(string $pattern): string
{
    $body = preg_replace('#^/(.*)/[a-z]*$#s', '$1', $pattern) ?? $pattern;
    // Drop escape sequences such as \s or \. by replacing the backslash and the character after it.
    $body = preg_replace('/' . preg_quote(chr(92), '/') . './s', ' ', $body) ?? $body;
    $parts = preg_split('/[\[\]\(\)\|\*\+\?\{\}\^\$\.\s]+/', $body) ?: [];

    $longest = '';
    foreach ($parts as $part) {
        if (mb_strlen($part) > mb_strlen($longest)) {
            $longest = $part;
        }
    }

    return normalizeForMatch($longest);
}

/**
 * Rejects candidates that look grounded but are not: a bare file path used as a content literal,
 * a regex character class that holds alternatives (e.g. [a|b], which matches single characters),
 * or a pattern whose literal text never appears in the sources the model was given.
 *
 * @param array<string, mixed> $candidate
 * @return string|null The rejection reason, or null if the candidate is acceptable.
 */
function checkCandidateShape(array $candidate, string $sourceText): ?string
{
    $pattern = (string)($candidate['pattern'] ?? '');
    $type = $candidate['pattern_type'] ?? '';

    if ($type === 'literal' && preg_match('#^[\w.\-]+(/[\w.\-]*)+/?$#', $pattern) === 1) {
        return 'pattern is a file path, not content a scanner can match inside a file';
    }

    // Letters, spaces and alternation bars only means English prose, which matches any article
    // about the attack and not the attack itself. Real markers contain code or IOC punctuation.
    $bare = $type === 'regex' ? (preg_replace('#^/(.*)/[a-z]*$#s', '$1', $pattern) ?? $pattern) : $pattern;
    if (preg_match('/^[\p{L}\s|]+$/u', $bare) === 1) {
        return 'pattern is plain English prose, which would match articles about the attack rather than the attack itself';
    }

    if ($type === 'regex' && preg_match('/\[[^\]]*\|[^\]]*\]/', $pattern) === 1) {
        return 'regex has "|" inside a character class; use (a|b) for alternatives';
    }

    $literal = $type === 'regex' ? longestRegexLiteral($pattern) : normalizeForMatch($pattern);
    if (mb_strlen($literal) < 6) {
        return 'pattern has too little literal text to verify against the sources';
    }

    if ($sourceText !== '' && !str_contains($sourceText, $literal)) {
        return 'pattern text "' . mb_substr($literal, 0, 60) . '" does not appear in any source the model was given';
    }

    return null;
}

/**
 * Says why a model reply produced no candidates, for the log.
 */
function explainEmptyReply(string $text): string
{
    if (trim($text) === '') {
        return 'the model returned an empty reply';
    }
    if (!preg_match('/\{.*\}/s', $text, $jsonMatch)) {
        return 'the reply contains no JSON object';
    }
    $parsed = json_decode($jsonMatch[0], true);
    if ($parsed === null) {
        return 'the JSON did not parse: ' . json_last_error_msg();
    }
    if (!isset($parsed['signatures']) || !is_array($parsed['signatures'])) {
        return 'the JSON has no "signatures" array';
    }

    return 'the "signatures" array is empty';
}

/**
 * Bump this whenever the prompt, the validator or the shape checks change. Rejections were made
 * under the old rules, so they are cleared and those candidates get another chance.
 */
const PIPELINE_RULES_VERSION = '2026-10-05.1';

/**
 * Loads the processed-source state kept on the state branch. A missing or unreadable file starts
 * an empty state, so the first run needs no setup. Rejections from an earlier rules version are
 * dropped here.
 *
 * @return array{rules_version: string, sources: array<string, array<string, string>>, rejected: array<string, array<string, string>>}
 */
function loadState(string $path): array
{
    $decoded = is_file($path) ? json_decode((string)file_get_contents($path), true) : null;
    $sameRules = ($decoded['rules_version'] ?? null) === PIPELINE_RULES_VERSION;

    return [
        'rules_version' => PIPELINE_RULES_VERSION,
        'sources' => is_array($decoded['sources'] ?? null) ? $decoded['sources'] : [],
        'rejected' => $sameRules && is_array($decoded['rejected'] ?? null) ? $decoded['rejected'] : [],
    ];
}

function saveState(string $path, array $state): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0777, true);
    }
    file_put_contents($path, json_encode($state, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
}

/**
 * Drops sources that have already been read. Each source is processed once; the state file is
 * what stops the same article using a triage slot every day.
 *
 * @param array<string, array{url: string, title: string, content: string}> $sources Keyed by URL.
 * @return array<string, array{url: string, title: string, content: string}>
 */
function excludeAlreadyRead(array $sources, array $state): array
{
    return array_filter($sources, static fn (string $url): bool => !isset($state['sources'][$url]), ARRAY_FILTER_USE_KEY);
}

/**
 * True when this candidate ID was rejected under the current rules, so the model is not shown the
 * same bad signature every day.
 */
function isRecentlyRejected(string $id, array $state): bool
{
    return isset($state['rejected'][$id]);
}

/**
 * Records the sources read this run, the signature each accepted candidate came from, and the
 * candidates rejected this run.
 *
 * @param list<string> $readUrls
 * @param array{accepted: list<array<string, mixed>>, rejected: array<string, list<string>>} $applied
 */
function recordRun(array $state, array $readUrls, array $applied, string $date): array
{
    $state['rules_version'] = PIPELINE_RULES_VERSION;
    foreach ($readUrls as $url) {
        $state['sources'][$url] = [
            'first_seen' => $state['sources'][$url]['first_seen'] ?? $date,
            'outcome' => $state['sources'][$url]['outcome'] ?? 'read',
        ];
    }
    foreach ($applied['accepted'] as $signature) {
        $url = (string)($signature['source'] ?? '');
        if (isset($state['sources'][$url])) {
            $state['sources'][$url]['outcome'] = 'produced ' . ($signature['id'] ?? '?');
        }
    }
    foreach ($applied['rejected'] as $id => $reasons) {
        $state['rejected'][(string)$id] = ['reason' => implode('; ', $reasons), 'date' => $date];
    }

    return $state;
}

/**
 * Vets each candidate (in order, up to $maxNew) against duplicate ids and
 * validateSignatureSet() - the same gate the CI validator applies to the whole file. Pure: no
 * I/O, so this is the part the tests exercise directly.
 *
 * @param list<array<string, mixed>> $candidates
 * @param array<string, mixed> $existing Decoded signatures.json.
 * @param list<string> $cleanFiles Absolute paths, pre-loaded via listFilesRecursively().
 * @param string $sourceText Normalized text of the sources given to the model; empty skips grounding.
 * @return array{accepted: list<array<string, mixed>>, rejected: array<string, list<string>>, existing: array<string, mixed>}
 */
function applyCandidates(array $candidates, array $existing, array $cleanFiles, int $maxNew, string $sourceText = ''): array
{
    $existingIds = array_column($existing['signatures'], 'id');
    $accepted = [];
    $rejected = [];

    foreach (array_slice($candidates, 0, $maxNew) as $candidate) {
        $id = $candidate['id'] ?? '(no id)';

        if (in_array($id, $existingIds, true)) {
            $rejected[$id] = ['duplicate of an existing signature id'];
            continue;
        }

        $shapeError = checkCandidateShape($candidate, $sourceText);
        if ($shapeError !== null) {
            $rejected[$id] = [$shapeError];
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

    if ($accepted !== []) {
        $existing['signatures'] = [...$existing['signatures'], ...$accepted];
        $existing['version'] = date('Y-m-d');
    }

    return ['accepted' => $accepted, 'rejected' => $rejected, 'existing' => $existing];
}

/**
 * @param list<array<string, mixed>> $accepted
 * @param array<string, list<string>> $rejected
 */
function buildPrBody(array $accepted, array $rejected, string $model): string
{
    $prBody = "## Proposed detection signatures\n\n"
        . "Generated by `propose_signatures.php` (model: `{$model}`, search: Tavily), auto-validated "
        . "against corpus/clean/ before being written here. **Review before merging.**\n\n";

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

    return $prBody;
}

/**
 * @return int Process exit code.
 */
function main(): int
{
    $model = getenv('WORKERS_AI_MODEL') ?: '@cf/meta/llama-3.3-70b-instruct-fp8-fast';
    $signaturesPath = getenv('SIG_PATH') ?: __DIR__ . '/../signatures.json';
    $cleanCorpusDir = getenv('CLEAN_CORPUS_DIR') ?: __DIR__ . '/../corpus/clean';
    $maxNew = (int)(getenv('MAX_NEW') ?: 5);
    $prBodyPath = getenv('PR_BODY_PATH') ?: __DIR__ . '/../pr_body.md';
    $debugPath = getenv('DEBUG_LOG_PATH') ?: __DIR__ . '/../propose_debug.log';
    file_put_contents($debugPath, 'Run started ' . date('c') . "\n");

    $cfToken = getenv('CLOUDFLARE_API_KEY');
    $cfAccount = getenv('CLOUDFLARE_ACCOUNT_ID');
    $tavilyKey = getenv('TAVILY_API_KEY') ?: '';
    $braveKey = getenv('BRAVE_SEARCH_API_KEY') ?: '';
    if (!$cfToken || !$cfAccount || ($tavilyKey === '' && $braveKey === '')) {
        fwrite(STDERR, "CLOUDFLARE_API_KEY and CLOUDFLARE_ACCOUNT_ID are required, plus TAVILY_API_KEY and/or BRAVE_SEARCH_API_KEY.\n");
        return 1;
    }

    $existingRaw = @file_get_contents($signaturesPath);
    $existing = $existingRaw !== false ? json_decode($existingRaw, true) : null;
    if (!is_array($existing) || !isset($existing['signatures']) || !is_array($existing['signatures'])) {
        fwrite(STDERR, "{$signaturesPath} is not valid JSON with a top-level \"signatures\" array\n");
        return 1;
    }

    // Research step: gather snippets from every query, de-duplicated by URL.
    $sources = [];
    foreach (RESEARCH_QUERIES as $query) {
        $searches = [];
        if ($tavilyKey !== '') {
            $searches[] = searchTavily($tavilyKey, $query);
        }
        if ($braveKey !== '') {
            $searches[] = searchBrave($braveKey, $query);
        }
        foreach ($searches as $search) {
            if (!$search['ok']) {
                fwrite(STDERR, $search['error'] . "\n");
                if ($search['fatal']) {
                    return 1;
                }
                continue;
            }
            foreach ($search['results'] as $hit) {
                $sources[$hit['url']] ??= $hit;
            }
        }
    }

    if ($sources === []) {
        echo "No research sources retrieved; nothing to propose.\n";
        return 0;
    }

    $statePath = getenv('STATE_PATH') ?: __DIR__ . '/../data/processed_sources.json';
    $state = loadState($statePath);
    $sources = excludeAlreadyRead($sources, $state);
    if ($sources === []) {
        echo "Every source was read within the refresh window; nothing new to propose.\n";
        return 0;
    }
    echo 'New or stale sources to consider: ' . count($sources) . "\n";

    file_put_contents($debugPath, "\n=== Candidate pool (" . count($sources) . ") ===\n" . implode("\n", array_keys($sources)) . "\n", FILE_APPEND);
    $triage = triageSources($sources, $cfToken, $cfAccount);
    file_put_contents($debugPath, "\n=== Triage: {$triage['neurons']} neurons, model " . TRIAGE_MODEL . " ===\n", FILE_APPEND);
    file_put_contents($debugPath, "Picked: " . implode(', ', $triage['urls']) . ($triage['error'] !== '' ? " ({$triage['error']})" : '') . "\n" . $triage['raw'] . "\n", FILE_APPEND);
    $sources = orderByPriority($sources, $triage['urls']);
    echo 'Triage picked ' . count($triage['urls']) . ' source(s), used ' . $triage['neurons'] . " neurons.\n";

    // Replace the search snippet with the full page text for the first few sources that can be
    // fetched. A page that blocks us (403, bot checks) keeps its snippet.
    $successes = 0;
    $attempts = 0;
    foreach ($sources as $url => $hit) {
        if ($successes >= FETCH_SUCCESSES || $attempts >= FETCH_ATTEMPTS) {
            break;
        }
        $attempts++;
        $html = fetchPage($url);
        if ($html === null) {
            continue;
        }
        $text = extractPageText($html);
        if ($text === '') {
            continue;
        }
        $sources[$url]['content'] = $text;
        $sources[$url]['fetched'] = true;
        $successes++;
    }
    echo "Fetched full text for {$successes} of {$attempts} attempted source(s).\n";

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
1. Base every candidate ONLY on the numbered sources provided by the user. Use literal code
   fragments, marker strings or injected-script patterns that the sources actually publish.
   Do not invent indicators.
2. Only propose a signature when there is a concrete, content-matchable artifact. If the
   sources contain none, propose nothing - quality over quantity.
3. Do not re-propose a concept already covered by an existing signature:
{$coveredSummary}
4. Each pattern is either "literal" (a plain substring) or "regex" (a PHP-PCRE pattern with
   delimiters and flags, e.g. "/pattern/i", preg_match-compatible). Prefer literal when a
   plain substring is enough. Keep a regex specific and anchored to the artifact; avoid anything
   broad enough to match legitimate analytics/consent/chat-widget scripts or ordinary PHP
   utility code.
5. Every signature must include 1-3 "test_should_match" samples (realistic, inert content it
   must match) and 1-3 "test_should_not_match" samples (realistic benign content it must NOT
   match). A candidate that fails its own samples will be rejected. Never write a working
   malicious payload as a sample - a realistic but inert shape is enough.
6. "target" is a list of: "pub_php" (PHP files under pub/media or pub/static),
   "cms_content" (CMS block/page HTML), "design_config" (admin-editable HTML/JS config values),
   "generated_php" (PHP under generated/code/).

Reply with ONLY a compact JSON object, no prose, no markdown fences:
{"signatures":[{"id":"short-stable-slug","name":"...","severity":"critical|warning",
"target":["cms_content"],"pattern_type":"literal|regex","pattern":"...","description":"...",
"test_should_match":["..."],"test_should_not_match":["..."],"source":"URL of the write-up it came from"}]}
PROMPT;

    $promptSources = selectSourcesForPrompt($sources);
    $readUrls = array_column($promptSources, 'url');
    $sourceText = normalizeForMatch(implode("\n", array_column($promptSources, 'content')));
    $sourceList = array_map(
        static fn (array $s): string => '  - ' . $s['url'] . ' (' . mb_strlen($s['content']) . ' chars)',
        $promptSources
    );
    file_put_contents($debugPath, "Model: {$model}\nSources in prompt (" . count($promptSources) . "):\n" . implode("\n", $sourceList) . "\n", FILE_APPEND);
    echo 'Sources in prompt: ' . count($promptSources) . "\n";

    $userPrompt = "Sources:\n\n" . formatSources($promptSources)
        . "\n\nPropose up to {$maxNew} new, high-confidence detection signatures supported by the "
        . "sources above.";

    $result = callWorkersAI($cfToken, $cfAccount, $model, $systemPrompt, $userPrompt);
    if (!$result['ok']) {
        fwrite(STDERR, $result['error'] . "\n");
        return $result['fatal'] ? 1 : 0;
    }

    $rawReply = $result['text'];
    file_put_contents($debugPath, "\n=== Drafting: {$result['neurons']} neurons, model {$model} ===\n", FILE_APPEND);
    echo 'Drafting used ' . $result['neurons'] . " neurons.\n";
    file_put_contents($debugPath, "\n=== Raw model reply (" . strlen($rawReply) . " bytes) ===\n" . $rawReply . "\n", FILE_APPEND);
    echo 'Model reply: ' . strlen($rawReply) . ' bytes; first 300: ' . substr($rawReply, 0, 300) . "\n";

    $candidates = extractCandidates($rawReply);
    if ($candidates === []) {
        $reason = explainEmptyReply($rawReply);
        file_put_contents($debugPath, "\n=== No candidates: {$reason} ===\n", FILE_APPEND);
        echo "No candidates found in the model's response: {$reason}.\n";
        // A reply that did not parse says nothing about the sources, so leave them unread and
        // let the next run try again. A reply that parsed and was empty counts as read.
        if (!str_starts_with($reason, 'the JSON')) {
            saveState($statePath, recordRun($state, $readUrls, ['accepted' => [], 'rejected' => []], date('Y-m-d')));
        }
        return 0;
    }

    $cleanFiles = listFilesRecursively($cleanCorpusDir);
    $candidates = array_values(array_filter(
        $candidates,
        static fn (array $c): bool => !isRecentlyRejected((string)($c['id'] ?? ''), $state)
    ));
    $applied = applyCandidates($candidates, $existing, $cleanFiles, $maxNew, $sourceText);

    $verdicts = ["\n=== Candidates (" . count($candidates) . ") ==="];
    foreach ($applied['accepted'] as $a) {
        $verdicts[] = "  ACCEPTED {$a['id']}";
    }
    foreach ($applied['rejected'] as $id => $reasons) {
        $verdicts[] = "  REJECTED {$id}: " . implode('; ', $reasons);
    }
    file_put_contents($debugPath, implode("\n", $verdicts) . "\n", FILE_APPEND);

    file_put_contents($prBodyPath, buildPrBody($applied['accepted'], $applied['rejected'], $model));

    if ($applied['accepted'] === []) {
        echo "No vetted signatures to propose.\n";
        saveState($statePath, recordRun($state, $readUrls, $applied, date('Y-m-d')));
        return 0;
    }

    file_put_contents(
        $signaturesPath,
        json_encode($applied['existing'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
    );

    saveState($statePath, recordRun($state, $readUrls, $applied, date('Y-m-d')));

    echo 'Added ' . count($applied['accepted']) . ' vetted signature(s); rejected '
        . count($applied['rejected']) . ".\n";

    return 0;
}

if (!defined('PROPOSE_SIGNATURES_TESTING')) {
    exit(main());
}
