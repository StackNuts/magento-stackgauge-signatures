<?php
/**
 * Writes an article's readable text, with code blocks first, to a file the drafter and
 * check_draft.php can use as --source.
 *
 * Usage: php scripts/fetch_article.php <url> <output-file>
 */

declare(strict_types=1);

define('DISCOVER_TESTING', 1);
require __DIR__ . '/discover.php';

if ($argc < 3) {
    fwrite(STDERR, "Usage: php scripts/fetch_article.php <url> <output-file>\n");
    exit(2);
}

$html = httpGet($argv[1]);
if ($html === null) {
    fwrite(STDERR, "Could not download {$argv[1]}\n");
    exit(1);
}

$text = articleText($html);
$dir = dirname($argv[2]);
if (!is_dir($dir)) {
    mkdir($dir, 0777, true);
}
file_put_contents($argv[2], $text . "\n");
echo 'Wrote ' . mb_strlen($text) . " characters to {$argv[2]}\n";
