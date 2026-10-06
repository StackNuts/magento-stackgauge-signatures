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
const IGNORED_DOMAINS = [
    'sansec.io', 'sucuri.net', 'malwarebytes.com', 'thehackernews.com', 'bleepingcomputer.com',
    'adobe.com', 'magento.com', 'google.com', 'github.com', 'twitter.com', 'linkedin.com', 'x.com',
    'facebook.com', 'youtube.com', 'cve.org', 'nist.gov', 'mitre.org', 'virustotal.com',
];

const FIRST_RUN_LOOKBACK_DAYS = 30;
const OVERLAP_DAYS = 2;
const MAX_ARTICLES_PER_RUN = 25;
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
    if (preg_match_all('#[A-Za-z0-9+/]{40,}={0,2}#', $text, $blobs)) {
        foreach (array_unique($blobs[0]) as $blob) {
            $decoded = base64_decode($blob, true);
            $context = $decoded !== false && ctype_print($decoded) ? 'decodes to: ' . $decoded : $blob;
            $add('base64', $blob, $context);
        }
    }

    if (preg_match_all('#\b(?:[a-z0-9-]+\.)+(?:com|net|org|xyz|top|app|tk|ml|ga|cf|site|online|live|store|info|ru|cc|me|io)\b#i', $text, $domains)) {
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

    if (preg_match_all('#\b[\w\-]+\.(?:php|phtml|phar)\b#i', $text, $files)) {
        foreach (array_unique($files[0]) as $file) {
            $add('file', $file, $file);
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
    $text = strtolower(html_entity_decode(strip_tags($html), ENT_QUOTES | ENT_HTML5, 'UTF-8'));

    return str_contains($text, 'magento') || str_contains($text, 'adobe commerce');
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
        $results[] = $article + ['indicators' => $indicators];
        $state['sources'][$article['url']] = ['first_seen' => $today, 'outcome' => 'read: ' . count($indicators) . ' indicator(s)'];
        echo count($indicators) . " indicator(s): {$article['url']}\n";
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

    $state['last_run'] = $today;
    saveState($statePath, $state);

    return 0;
}

if (!defined('DISCOVER_TESTING')) {
    exit(main());
}
