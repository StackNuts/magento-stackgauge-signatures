<?php
/**
 * Lists the regex rules in an OWASP CoreRuleSet .conf file, so a drafter can turn them into
 * signatures. Prints one block per rule: id, the rule's msg, and the @rx pattern as written.
 *
 * Usage: php scripts/crs_rules.php <path-or-url-to-conf>
 *
 * CoreRuleSet patterns are PCRE without delimiters, and the source is licensed Apache-2.0. Keep the
 * rule id and the licence notice in each signature's source field when you convert them.
 */

declare(strict_types=1);

$target = $argv[1] ?? '';
if ($target === '') {
    fwrite(STDERR, "Usage: php scripts/crs_rules.php <path-or-url-to-conf>\n");
    exit(2);
}

$text = str_starts_with($target, 'http')
    ? (string)file_get_contents($target, false, stream_context_create(['http' => ['timeout' => 30, 'user_agent' => 'magento-rule-author']]))
    : (string)file_get_contents($target);
if ($text === '') {
    fwrite(STDERR, "Could not read {$target}\n");
    exit(1);
}

// Join continuation lines (CRS ends a line with a backslash) so each SecRule is one string.
$text = preg_replace("/\\\\\r?\n/", ' ', $text) ?? $text;

$count = 0;
foreach (preg_split('/\r?\n/', $text) as $line) {
    $line = trim($line);
    if (!str_starts_with($line, 'SecRule') || !str_contains($line, '@rx')) {
        continue;
    }
    if (!preg_match('/@rx\s+((?:[^"\\\\]|\\\\.)*)"/s', $line, $rx)) {
        continue;
    }
    $id = preg_match('/id:(\d+)/', $line, $m) ? $m[1] : '?';
    $msg = preg_match("/msg:'([^']*)'/", $line, $mm) ? $mm[1] : '';
    $pattern = str_replace('\\"', '"', $rx[1]);
    echo "id {$id}  {$msg}\n  @rx {$pattern}\n\n";
    $count++;
}

echo "{$count} regex rule(s) in {$target}\n";
