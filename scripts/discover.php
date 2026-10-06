<?php
/**
 * Finds research articles published since the last run on a small set of publishers, reads them,
 * and writes the indicator strings found in each to a candidates file for human review.
 *
 * This script never writes signatures.json. Signatures are written by hand from the candidates,
 * then checked by scripts/validate_signatures.php.
 *
 * Discovery reads the Sansec sitemap (its <lastmod> dates) and RSS feeds (their pubDate). Each
 * article is processed once; the state file records what has been read, so the date window only
 * limits how far back a run looks.
 */

declare(strict_types=1);

require __DIR__ . '/lib/matching.php';

const SANSEC_SITEMAP_URL = 'https://sansec.io/sitemap.xml';
const SANSEC_RESEARCH_PREFIX = 'https://sansec.io/research/';

/** Feed URL => whether to keep only items that mention Magento-related terms. */
const FEEDS = [
    'https://blog.sucuri.net/feed' => true,
    'https://www.malwarebytes.com/blog/feed' => true,
    'https://thehackernews.com/feeds/posts/default' => true,
];

const MAGENTO_TERMS = ['magento', 'adobe commerce', 'magecart', 'skimmer', 'webshell', 'e-commerce', 'ecommerce'];

/** Publisher and vendor domains that appear in articles but are not indicators. */
/** Top-level domains seen in indicator domains. Known TLDs keep JavaScript names from matching. */
const DOMAIN_TLDS = [
    'com', 'net', 'org', 'xyz', 'top', 'app', 'tk', 'ml', 'ga', 'cf', 'gq', 'site', 'online', 'live', 'store',
    'shop', 'website', 'icu', 'info', 'biz', 'club', 'pw', 'cyou', 'buzz', 'link', 'help', 'click', 'sbs',
    'ru', 'cc', 'me', 'io', 'to', 'tv', 'ws', 'sh', 'co', 'us', 'uk', 'de', 'in', 'cn', 'br',
];

/** File extensions worth keeping as indicators: scripts, binaries and text drops. */
const FILE_EXTENSIONS = ['php', 'phtml', 'phar', 'txt', 'exe', 'dll', 'cmd', 'bat', 'ps1', 'sh', 'js', 'jar', 'so', 'bin'];

const IGNORED_DOMAINS = [
    'sansec.io', 'sucuri.net', 'malwarebytes.com', 'thehackernews.com', 'bleepingcomputer.com',
    'adobe.com', 'magento.com', 'google.com', 'github.com', 'twitter.com', 'linkedin.com', 'x.com',
    'facebook.com', 'youtube.com', 'cve.org', 'nist.gov', 'mitre.org', 'virustotal.com', 'ecomscan.com',
];

const FIRST_RUN_LOOKBACK_DAYS = 30;
const OVERLAP_DAYS = 2;
const MAX_ARTICLES_PER_RUN = 10;
const DRAFT_MODEL = '@cf/openai/gpt-oss-120b';
const DRAFT_MAX_TOKENS = 6000;
const NEURON_BUDGET = 6000;
const NEURONS_PER_DRAFT_ESTIMATE = 600;
const ARTICLE_CHARS = 20000;
const MENU_SIZE = 40;
const PAGE_CHARS = 20000;
const CONTEXT_CHARS = 160;

/**
 * Downloads a URL. Returns null on any failure, so one blocked publisher does not stop the run.
 */
function httpGet(string $url): ?string
{
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_USERAGENT => 'Mozilla/5.0',
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_MAXFILESIZE => 3000000,
    ]);
    $body = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return $body === false || $httpCode >= 400 ? null : $body;
}

/**
 * Reads a sitemap into [url, lastmod] pairs, keeping only research articles.
 *
 * @return list<array{url: string, date: string}>
 */
function parseSitemap(string $xml): array
{
    $items = [];
    if (preg_match_all('#<url>\s*<loc>([^<]+)</loc>\s*<lastmod>([^<]+)</lastmod>#', $xml, $m, PREG_SET_ORDER) === false) {
        return [];
    }
    foreach ($m as $row) {
        $url = trim($row[1]);
        if (str_starts_with($url, SANSEC_RESEARCH_PREFIX)) {
            $items[] = ['url' => $url, 'date' => substr(trim($row[2]), 0, 10)];
        }
    }

    return $items;
}

/**
 * Reads an RSS feed into items with url, title, date and text.
 *
 * @return list<array{url: string, title: string, date: string, text: string}>
 */
function parseFeed(string $xml): array
{
    $items = [];
    preg_match_all('#<item>(.*?)</item>#s', $xml, $blocks);
    foreach ($blocks[1] as $block) {
        $link = preg_match('#<link>\s*([^<\s]+)\s*</link>#', $block, $l) ? trim($l[1]) : '';
        $title = preg_match('#<title>(.*?)</title>#s', $block, $t) ? feedText($t[1]) : '';
        $date = preg_match('#<pubDate>([^<]+)</pubDate>#', $block, $d) ? date('Y-m-d', strtotime(trim($d[1])) ?: 0) : '';
        $desc = preg_match('#<description>(.*?)</description>#s', $block, $s) ? feedText($s[1]) : '';
        if ($link !== '') {
            $items[] = ['url' => $link, 'title' => trim($title), 'date' => $date, 'text' => trim($desc)];
        }
    }

    return $items;
}

/**
 * Turns a feed field into plain text. CDATA must be unwrapped first, because strip_tags() would
 * otherwise delete everything inside it.
 */
function feedText(string $field): string
{
    $unwrapped = preg_replace('#<!\[CDATA\[(.*?)\]\]>#s', '$1', $field) ?? $field;

    return trim(html_entity_decode(strip_tags($unwrapped), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
}

/** True when the item's title or summary mentions a Magento-related term. */
function mentionsMagento(string $title, string $text): bool
{
    $haystack = strtolower($title . ' ' . $text);
    foreach (MAGENTO_TERMS as $term) {
        if (str_contains($haystack, $term)) {
            return true;
        }
    }

    return false;
}

/**
 * Keeps items dated on or after $since that are not already in the state.
 *
 * @param list<array{url: string, date: string}> $items
 * @return list<array{url: string, date: string}>
 */
function selectNew(array $items, array $state, string $since): array
{
    $fresh = [];
    foreach ($items as $item) {
        if (!isset($state['sources'][$item['url']]) && $item['date'] >= $since) {
            $fresh[$item['url']] = $item;
        }
    }
    usort($fresh, static fn (array $a, array $b): int => $b['date'] <=> $a['date']);

    return array_values($fresh);
}

/**
 * Pulls indicator strings out of an article's HTML. Each indicator keeps a short context so the
 * reviewer can see where it came from. Returns [kind => text, context] pairs, de-duplicated.
 *
 * @return list<array{kind: string, text: string, context: string}>
 */
function extractIndicators(string $html): array
{
    $html = mb_scrub($html, 'UTF-8');
    $found = [];
    $add = static function (string $kind, string $text, string $context) use (&$found): void {
        $key = $kind . "\0" . $text;
        if (!isset($found[$key]) && $text !== '') {
            $found[$key] = ['kind' => $kind, 'text' => $text, 'context' => mb_substr(preg_replace('/\s+/', ' ', $context) ?? '', 0, CONTEXT_CHARS)];
        }
    };

    $text = html_entity_decode(strip_tags(preg_replace('#<(script|style|noscript)\b[^>]*>.*?</\1>#is', ' ', $html) ?? ''), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    $text = mb_substr($text, 0, PAGE_CHARS);

    // Code blocks: the most reliable source of literal strings.
    if (preg_match_all('#<(pre|code)\b[^>]*>(.*?)</\1>#is', $html, $blocks)) {
        foreach ($blocks[2] as $block) {
            $code = trim(html_entity_decode(strip_tags($block), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            if (mb_strlen($code) >= 20) {
                $add('code', mb_substr($code, 0, 600), $code);
            }
        }
    }

    // Long base64 blobs, with the decoded text shown when it is printable.
    if (preg_match_all('#(?=[A-Za-z0-9+/]*[0-9+/])[A-Za-z0-9+/]{40,}={0,2}#', $text, $blobs)) {
        foreach (array_unique($blobs[0]) as $blob) {
            $decoded = base64_decode($blob, true);
            $context = $decoded !== false && ctype_print($decoded) ? 'decodes to: ' . $decoded : $blob;
            $add('base64', $blob, $context);
        }
    }

    if (preg_match_all('#\b(?:[a-z0-9-]+\.)+(?:' . implode('|', DOMAIN_TLDS) . ')\b#i', $text, $domains)) {
        foreach (array_unique($domains[0]) as $domain) {
            $root = implode('.', array_slice(explode('.', strtolower($domain)), -2));
            if (!in_array($root, IGNORED_DOMAINS, true)) {
                $add('domain', strtolower($domain), $domain);
            }
        }
    }

    if (preg_match_all('#\b(?:\d{1,3}\.){3}\d{1,3}\b#', $text, $ips)) {
        foreach (array_unique($ips[0]) as $ip) {
            $add('ip', $ip, $ip);
        }
    }

    if (preg_match_all('#\b[\w\-]+\.(?:' . implode('|', FILE_EXTENSIONS) . ')\b#i', $text, $files)) {
        foreach (array_unique($files[0]) as $file) {
            $add('file', $file, $file);
        }
    }

    if (preg_match_all('#\bGTM-[A-Z0-9]{6,}\b#', $text, $gtm)) {
        foreach (array_unique($gtm[0]) as $id) {
            $add('gtm', $id, $id);
        }
    }

    if (preg_match_all('#\bss\d+_[a-f0-9]{8,}\b#', $text, $markers)) {
        foreach (array_unique($markers[0]) as $marker) {
            $add('marker', $marker, $marker);
        }
    }

    if (preg_match_all('#(?:/dev/shm|/var/tmp|/tmp|/run/user/\w+|~/\.[\w.\-]+(?:/[\w.\-]+)*|/var/www/[\w./\-]+)#', $text, $paths)) {
        foreach (array_unique($paths[0]) as $path) {
            $add('path', rtrim($path, '/'), $path);
        }
    }

    if (preg_match_all('#\b(?:eval|base64_decode|strrev|gzinflate|assert|system|shell_exec|passthru|atob|btoa|fromCharCode|sendBeacon)\s*\(#', $text, $calls, PREG_OFFSET_CAPTURE)) {
        foreach ($calls[0] as [$call, $offset]) {
            $add('call', trim($call), substr($text, max(0, $offset - 60), 160));
        }
    }

    return array_values($found);
}

/**
 * True when an article is about Magento or Adobe Commerce. Generic skimmer or malware write-ups
 * that only mention Magento in passing are skipped, so the candidates stay Magento-specific.
 */
function isMagentoArticle(string $html): bool
{
    // Magento in the title or a heading means the article is about it. Sidebar and promo text
    // repeats the name in some pages, so in the body we require several mentions.
    $heading = '';
    if (preg_match_all('#<(title|h1)\b[^>]*>(.*?)</\1>#is', $html, $m)) {
        $heading = strtolower(strip_tags(implode(' ', $m[2])));
    }
    $terms = ['magento', 'adobe commerce'];
    foreach ($terms as $term) {
        if (str_contains($heading, $term)) {
            return true;
        }
    }

    // Sansec pages carry a fixed promo for its scanner, which names Magento. Drop those sentences first.
    $text = strtolower(html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
    $text = preg_replace('/[^.!?\n]*(?:ecomscan|scanner for|block all known)[^.!?\n]*[.!?]?/i', ' ', $text) ?? $text;
    $mentions = 0;
    foreach ($terms as $term) {
        $mentions += substr_count($text, $term);
    }

    return $mentions >= 2;
}
/**
 * Reads the state file. A missing file starts an empty state.
 *
 * @return array{last_run: string, sources: array<string, array<string, string>>}
 */
function loadState(string $path): array
{
    $decoded = is_file($path) ? json_decode((string)file_get_contents($path), true) : null;

    return [
        'last_run' => is_array($decoded) && is_string($decoded['last_run'] ?? null) ? $decoded['last_run'] : '',
        'sources' => is_array($decoded['sources'] ?? null) ? $decoded['sources'] : [],
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
 * Gathers the articles to read: Sansec research from the sitemap, and recent items from each feed.
 *
 * @return list<array{url: string, date: string, title: string, feedText: string}>
 */
function gatherArticles(string $since, array $state): array
{
    $articles = [];

    $sitemap = httpGet(SANSEC_SITEMAP_URL);
    if ($sitemap !== null) {
        foreach (selectNew(parseSitemap($sitemap), $state, $since) as $item) {
            $articles[$item['url']] = ['url' => $item['url'], 'date' => $item['date'], 'title' => '', 'feedText' => ''];
        }
    }

    foreach (FEEDS as $feedUrl => $magentoOnly) {
        $xml = httpGet($feedUrl);
        if ($xml === null) {
            echo "Feed unavailable: {$feedUrl}\n";
            continue;
        }
        foreach (parseFeed($xml) as $item) {
            if ($item['date'] < $since || isset($state['sources'][$item['url']])) {
                continue;
            }
            if ($magentoOnly && !mentionsMagento($item['title'], $item['text'])) {
                continue;
            }
            $articles[$item['url']] = ['url' => $item['url'], 'date' => $item['date'], 'title' => $item['title'], 'feedText' => $item['text']];
        }
    }

    usort($articles, static fn (array $a, array $b): int => $b['date'] <=> $a['date']);

    return $articles;
}

/** Plain article text for the drafting model: code blocks first, then the article body. */
function articleText(string $html): string
{
    $html = mb_scrub($html, 'UTF-8');
    $code = [];
    if (preg_match_all('#<(pre|code)\b[^>]*>(.*?)</\1>#is', $html, $m)) {
        foreach ($m[2] as $block) {
            $t = trim(html_entity_decode(strip_tags($block), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
            if (mb_strlen($t) >= 20) {
                $code[] = $t;
            }
        }
    }
    $body = preg_replace('#<(script|style|noscript|svg)\b[^>]*>.*?</\1>#is', ' ', $html) ?? '';
    $text = trim(preg_replace('/\s+/', ' ', html_entity_decode(strip_tags($body), ENT_QUOTES | ENT_HTML5, 'UTF-8')) ?? '');
    $combined = $code === [] ? $text : "CODE BLOCKS:\n" . implode("\n---\n", $code) . "\n\nARTICLE TEXT:\n" . $text;

    return mb_substr($combined, 0, ARTICLE_CHARS);
}

/**
 * The numbered menu the drafting model may choose from: domains, base64 blobs, file names, IPs and
 * calls first, then short code. Capped at MENU_SIZE so the prompt stays small.
 *
 * @return list<array{kind: string, text: string}>
 */
function menuFrom(array $indicators): array
{
    $order = ['domain' => 0, 'base64' => 1, 'file' => 2, 'ip' => 3, 'call' => 4, 'code' => 5];
    $usable = array_values(array_filter(
        $indicators,
        static fn (array $i): bool => isset($order[$i['kind']]) && ($i['kind'] !== 'code' || mb_strlen($i['text']) <= 200)
    ));
    usort($usable, static fn (array $a, array $b): int => $order[$a['kind']] <=> $order[$b['kind']]);

    $menu = [];
    foreach (array_slice($usable, 0, MENU_SIZE) as $i) {
        $menu[] = ['kind' => $i['kind'], 'text' => mb_substr(str_replace("\n", ' ', $i['text']), 0, 160)];
    }

    return $menu;
}

/**
 * One call to the drafting model. Returns the reply text, the neurons used and any error.
 *
 * @return array{ok: bool, text: string, neurons: float, error: string}
 */
function callDraftModel(string $accountId, string $apiToken, string $system, string $user): array
{
    $body = json_encode([
        'messages' => [['role' => 'system', 'content' => $system], ['role' => 'user', 'content' => $user]],
        'max_tokens' => DRAFT_MAX_TOKENS,
        'temperature' => 0,
    ]);
    $ch = curl_init("https://api.cloudflare.com/client/v4/accounts/{$accountId}/ai/run/" . DRAFT_MODEL);
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', "Authorization: Bearer {$apiToken}"],
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 240,
    ]);
    $raw = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $response = is_string($raw) ? json_decode($raw, true) : null;
    if ($raw === false || $httpCode >= 400 || !is_array($response['result'] ?? null)) {
        return ['ok' => false, 'text' => '', 'neurons' => 0.0, 'error' => 'HTTP ' . $httpCode . ': ' . substr((string)$raw, 0, 200)];
    }
    $result = $response['result'];

    return [
        'ok' => true,
        'text' => (string)($result['choices'][0]['message']['content'] ?? ''),
        'neurons' => (float)($result['usage']['neurons'] ?? 0),
        'error' => '',
    ];
}

/** A short, filesystem-safe id from a group name. */
function slugify(string $text): string
{
    $slug = trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($text)) ?? '', '-');

    return $slug === '' ? 'indicator-group' : $slug;
}

/**
 * Builds one signature from a group of menu items. The code writes the pattern and the samples, so
 * the model never writes a string. Returns null, with the reason, when the group cannot be built
 * safely: mixed kinds, file names, or base64 items without a shared prefix.
 *
 * @param list<array{kind: string, text: string}> $items
 * @return array{signature: array<string, mixed>|null, reason: string}
 */
function signatureFromGroup(string $name, string $severity, array $items, string $url, string $why): array
{
    $kinds = array_values(array_unique(array_column($items, 'kind')));
    if (count($kinds) !== 1) {
        return ['signature' => null, 'reason' => 'items mix kinds (' . implode(', ', $kinds) . '); split the group'];
    }
    $kind = $kinds[0];
    $texts = array_column($items, 'text');
    $single = count($texts) === 1;
    $target = $kind === 'path' ? ['pub_php'] : ['cms_content', 'design_config'];
    $notMatch = ['<script src="https://cdn.example-shop.com/app.js"></script>', 'See the example.org documentation.'];

    switch ($kind) {
        case 'domain':
        case 'ip':
        case 'gtm':
        case 'marker':
            $sample = match ($kind) {
                'domain' => '<script src="https://' . $texts[0] . '/x.js"></script>',
                'ip' => "fetch('http://" . $texts[0] . "/c2')",
                'gtm' => "<script>gtag('config', '" . $texts[0] . "');</script>",
                default => 'var m = "' . $texts[0] . '";',
            };
            $pattern = $single ? $texts[0] : '/\b(?:' . implode('|', array_map(fn ($t) => preg_quote($t, '/'), $texts)) . ')\b/i';
            $type = $single ? 'literal' : 'regex';
            break;

        case 'base64':
            $prefix = $texts[0];
            foreach ($texts as $t) {
                $n = 0;
                while ($n < min(strlen($prefix), strlen($t)) && $prefix[$n] === $t[$n]) {
                    $n++;
                }
                $prefix = substr($prefix, 0, $n);
            }
            if (strlen($prefix) < 12) {
                return ['signature' => null, 'reason' => 'base64 items share no prefix of 12 characters'];
            }
            $pattern = $prefix;
            $type = 'literal';
            $sample = 'var d = "' . $prefix . '";';
            break;

        case 'path':
        case 'call':
        case 'code':
            if (!$single || mb_strlen($texts[0]) > 200) {
                return ['signature' => null, 'reason' => 'only a single short ' . $kind . ' item can become a signature'];
            }
            $pattern = $texts[0];
            $type = 'literal';
            $sample = $kind === 'path' ? 'ls ' . $texts[0] : '<p>' . $texts[0] . '</p>';
            break;

        default:
            return ['signature' => null, 'reason' => "kind {$kind} cannot become a signature"];
    }

    return ['signature' => [
        'id' => slugify($name) . '-' . $kind,
        'name' => $name,
        'severity' => $severity,
        'source' => $url,
        'target' => $target,
        'pattern_type' => $type,
        'pattern' => $pattern,
        'description' => trim($why) . ' Source: ' . $url . '.',
        'test_should_match' => [$sample],
        'test_should_not_match' => $notMatch,
    ], 'reason' => ''];
}

/**
 * Drafts signatures for one article. The model only chooses menu numbers and names a group; the code
 * builds each signature, and the validator checks it against the clean corpus.
 *
 * @param list<array{kind: string, text: string}> $menu
 * @return array{drafts: list<array{signature: array<string, mixed>|null, errors: list<string>, reason: string}>, neurons: float, error: string, reply: string}
 */
function draftSignatures(string $url, string $html, array $menu, string $accountId, string $apiToken): array
{
    $system = 'You select indicators for Magento detection from ONE article. Reply with ONLY JSON: '
        . '{"groups":[{"name":"short name","severity":"critical|warning","items":[menu numbers],"why":"one sentence"}]}. '
        . 'Rules: 1. Use ONLY menu numbers from the menu. 2. Put items that belong to one campaign and one kind in one group. '
        . '3. Skip publisher, vendor, CVE and legitimate-service references. 4. Magento-related indicators only. '
        . 'If none qualify, return {"groups":[]}.';

    $lines = [];
    foreach ($menu as $n => $i) {
        $lines[] = ($n + 1) . ". [{$i['kind']}] {$i['text']}";
    }
    $user = "Article ({$url}):\n" . articleText($html) . "\n\nMenu:\n" . implode("\n", $lines);

    $reply = callDraftModel($accountId, $apiToken, $system, $user);
    if (!$reply['ok']) {
        return ['drafts' => [], 'neurons' => $reply['neurons'], 'error' => $reply['error'], 'reply' => ''];
    }

    $parsed = preg_match('/\{.*\}/s', $reply['text'], $json) ? json_decode($json[0], true) : null;
    $groups = is_array($parsed['groups'] ?? null) ? $parsed['groups'] : [];
    $clean = listFilesRecursively(dirname(__DIR__) . '/corpus/clean');

    $drafts = [];
    foreach ($groups as $group) {
        if (!is_array($group)) {
            continue;
        }
        $items = [];
        foreach (array_unique(array_filter((array)($group['items'] ?? []), 'is_int')) as $n) {
            if ($n >= 1 && $n <= count($menu)) {
                $items[] = $menu[$n - 1];
            }
        }
        if ($items === []) {
            continue;
        }
        $name = (string)($group['name'] ?? 'indicator group');
        $severity = in_array($group['severity'] ?? '', ['critical', 'warning'], true) ? $group['severity'] : 'warning';
        // One signature per kind: a group that mixes kinds is split, since each kind needs its own pattern.
        $byKind = [];
        foreach ($items as $item) {
            $byKind[$item['kind']][] = $item;
        }
        foreach ($byKind as $kind => $kindItems) {
            $built = signatureFromGroup($name . ' (' . $kind . ')', $severity, $kindItems, $url, (string)($group['why'] ?? ''));
            if ($built['signature'] === null) {
                $drafts[] = ['signature' => null, 'errors' => ['not built: ' . $built['reason']], 'reason' => $name];
                continue;
            }
            $drafts[] = ['signature' => $built['signature'], 'errors' => validateSignatureSet([$built['signature']], $clean), 'reason' => $name];
        }
    }

    return ['drafts' => $drafts, 'neurons' => $reply['neurons'], 'error' => $parsed === null ? 'reply was not JSON' : '', 'reply' => $reply['text']];
}

/**
 * @return int Process exit code.
 */
function main(): int
{
    $statePath = getenv('STATE_PATH') ?: __DIR__ . '/../data/processed_sources.json';
    $candidatesDir = getenv('CANDIDATES_DIR') ?: __DIR__ . '/../data/candidates';
    $today = date('Y-m-d');

    $state = loadState($statePath);
    $since = $state['last_run'] !== ''
        ? date('Y-m-d', strtotime($state['last_run']) - OVERLAP_DAYS * 86400)
        : date('Y-m-d', time() - FIRST_RUN_LOOKBACK_DAYS * 86400);

    $articles = array_slice(gatherArticles($since, $state), 0, MAX_ARTICLES_PER_RUN);
    echo "Since {$since}: " . count($articles) . " new article(s) to read.\n";

    $accountId = getenv('CLOUDFLARE_ACCOUNT_ID') ?: '';
    $apiToken = getenv('CLOUDFLARE_API_KEY') ?: '';
    $neuronsSpent = 0.0;
    $results = [];
    foreach ($articles as $article) {
        $html = httpGet($article['url']);
        if ($html === null) {
            echo "Blocked, left unread: {$article['url']}\n";
            continue;
        }
        if (!isMagentoArticle($html)) {
            $state['sources'][$article['url']] = ['first_seen' => $today, 'outcome' => 'skipped: not about Magento'];
            echo "Skipped, not about Magento: {$article['url']}\n";
            continue;
        }
        $indicators = extractIndicators($html);
        $entry = $article + ['indicators' => $indicators, 'drafts' => []];
        $state['sources'][$article['url']] = ['first_seen' => $today, 'outcome' => 'read: ' . count($indicators) . ' indicator(s)'];
        echo count($indicators) . " indicator(s): {$article['url']}\n";

        if ($accountId !== '' && $apiToken !== '') {
            if ($neuronsSpent + NEURONS_PER_DRAFT_ESTIMATE > NEURON_BUDGET) {
                echo "Neuron budget reached; not drafting: {$article['url']}\n";
            } else {
                $draft = draftSignatures($article['url'], $html, menuFrom($indicators), $accountId, $apiToken);
                $neuronsSpent += $draft['neurons'];
                $entry['drafts'] = $draft['drafts'];
                $entry['draft_error'] = $draft['error'];
                $entry['draft_reply'] = $draft['reply'] ?? '';
                $valid = count(array_filter($draft['drafts'], fn (array $d): bool => $d['errors'] === []));
                echo "Drafted " . count($draft['drafts']) . " ({$valid} valid), " . round($draft['neurons']) . " neurons: {$article['url']}\n";
            }
        }
        $results[] = $entry;
    }

    if ($results !== []) {
        if (!is_dir($candidatesDir)) {
            mkdir($candidatesDir, 0777, true);
        }
        file_put_contents(
            $candidatesDir . "/{$today}.json",
            json_encode($results, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE) . "\n"
        );
    }

    echo 'Neurons used by drafting this run: ' . round($neuronsSpent) . "\n";
    $state['last_run'] = $today;
    saveState($statePath, $state);

    return 0;
}

if (!defined('DISCOVER_TESTING')) {
    exit(main());
}
