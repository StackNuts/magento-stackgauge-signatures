<?php
/**
 * Self-tests for discover.php: sitemap and feed parsing, the Magento filter, the date window,
 * indicator extraction and state handling. Run with: php scripts/test_discover.php
 */

declare(strict_types=1);

define('DISCOVER_TESTING', 1);
require __DIR__ . '/discover.php';

$failures = [];
$check = static function (bool $ok, string $message) use (&$failures): void {
    if (!$ok) {
        $failures[] = $message;
    }
};

// Sitemap: only research articles, with their lastmod dates.
$sitemap = '<urlset><url><loc>https://sansec.io/research/a-post</loc><lastmod>2026-09-01T10:00:00Z</lastmod></url>'
    . '<url><loc>https://sansec.io/tags/magento</loc><lastmod>2026-09-02T10:00:00Z</lastmod></url></urlset>';
$items = parseSitemap($sitemap);
$check(count($items) === 1 && $items[0]['url'] === 'https://sansec.io/research/a-post', 'sitemap should keep research pages only');
$check(($items[0]['date'] ?? '') === '2026-09-01', 'sitemap should keep the lastmod date');

// RSS: CDATA titles and descriptions must survive.
$feed = '<rss><channel><item><title><![CDATA[New skimmer hits Magento stores]]></title>'
    . '<link>https://example.org/skimmer</link><pubDate>Mon, 05 Oct 2026 10:00:00 +0000</pubDate>'
    . '<description><![CDATA[Card data stolen.]]></description></item></channel></rss>';
$rss = parseFeed($feed);
$check(count($rss) === 1 && $rss[0]['title'] === 'New skimmer hits Magento stores', 'feed titles inside CDATA should be kept');
$check(($rss[0]['date'] ?? '') === '2026-10-05', 'feed pubDate should become a date');
$check(mentionsMagento($rss[0]['title'], $rss[0]['text']), 'a Magento title should pass the relevance filter');
$check(!mentionsMagento('Quarterly earnings beat expectations', 'Shares rose.'), 'an unrelated item should fail the relevance filter');

// Date window: only items on or after the cut-off, and not already in the state.
$window = [
    ['url' => 'https://sansec.io/research/old', 'date' => '2026-01-01'],
    ['url' => 'https://sansec.io/research/new', 'date' => '2026-10-04'],
    ['url' => 'https://sansec.io/research/seen', 'date' => '2026-10-04'],
];
$state = ['last_run' => '', 'sources' => ['https://sansec.io/research/seen' => ['outcome' => 'read']]];
$selected = selectNew($window, $state, '2026-10-01');
$check(count($selected) === 1 && $selected[0]['url'] === 'https://sansec.io/research/new', 'selectNew should keep only new items inside the window');

// Extraction: code blocks, base64 with its decoded text, a domain, an IP, a file name and a call.
$html = '<p>The skimmer runs <code>eval(base64_decode($_POST["x"]));</code> from <b>statistics-for-you.com</b> at 23.137.249.67 via /fb_metrics.php.</p>'
    . '<p>Payload: ZXZhbChiYXNlNjRfZGVjb2RlKCJhYmNkZWZnaGlqa2xtbm9wIikpOw==</p>';
$indicators = extractIndicators($html);
$kinds = array_column($indicators, 'kind');
$texts = array_column($indicators, 'text');
$check(in_array('code', $kinds, true), 'extraction should keep code blocks');
$check(in_array('domain', $kinds, true) && in_array('statistics-for-you.com', $texts, true), 'extraction should find the skimmer domain');
$check(in_array('ip', $kinds, true) && in_array('23.137.249.67', $texts, true), 'extraction should find the IP address');
$check(in_array('file', $kinds, true) && in_array('fb_metrics.php', $texts, true), 'extraction should find the PHP file name');
$base64 = array_values(array_filter($indicators, fn ($i) => $i['kind'] === 'base64'));
$check(count($base64) === 1 && str_contains($base64[0]['context'], 'decodes to'), 'extraction should show what a base64 blob decodes to');
$check(!in_array('sansec.io', $texts, true), 'publisher domains should be ignored');

$check(isMagentoArticle('<p>Magento stores hit by a skimmer.</p>'), 'an article about Magento should pass the gate');
$check(!isMagentoArticle('<p>A WordPress plugin was hijacked.</p>'), 'an article about another platform should be skipped');

// State: a round trip keeps the last run and the sources.
$tmp = sys_get_temp_dir() . '/discover-state-test-' . getmypid() . '.json';
saveState($tmp, ['last_run' => '2026-10-05', 'sources' => ['https://sansec.io/research/x' => ['outcome' => 'read']]]);
$loaded = loadState($tmp);
$check($loaded['last_run'] === '2026-10-05' && isset($loaded['sources']['https://sansec.io/research/x']), 'state should survive a save and load');
unlink($tmp);
$check(loadState('/nonexistent/path.json')['sources'] === [], 'a missing state file should load as empty');

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " test failure(s):\n");
    foreach ($failures as $failure) {
        fwrite(STDERR, "  - {$failure}\n");
    }
    exit(1);
}

echo "All discover.php self-tests passed.\n";
