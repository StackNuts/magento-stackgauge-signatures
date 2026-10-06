<?php
/**
 * Checks a drafted batch of signatures before anyone adds them to signatures.json.
 *
 * Usage: php scripts/check_draft.php <draft.json> [--source <text-file>] [--apply]
 *
 * Each signature is checked with the same validator as CI (compiles, matches its own samples,
 * matches nothing in corpus/clean/), against the existing set (duplicate ids and patterns), and,
 * when --source is given, against the source text it was drafted from (the rule must match at
 * least one line of that text, so a rule cannot be drafted from nothing).
 *
 * Without --apply this only reports. With --apply, the accepted signatures are appended to
 * signatures.json and the version is bumped. Nothing is written otherwise.
 */

declare(strict_types=1);

require __DIR__ . '/lib/matching.php';

const ROOT = __DIR__ . '/..';

function usage(): never
{
    fwrite(STDERR, "Usage: php scripts/check_draft.php <draft.json> [--source <text-file>] [--apply]\n");
    exit(2);
}

$args = array_slice($argv, 1);
$apply = in_array('--apply', $args, true);
$sourceIdx = array_search('--source', $args, true);
$sourceFile = $sourceIdx !== false ? ($args[$sourceIdx + 1] ?? null) : null;
$draftFile = null;
foreach ($args as $i => $a) {
    if ($a !== '--apply' && $a !== '--source' && ($sourceIdx === false || $i !== $sourceIdx + 1)) {
        $draftFile = $a;
    }
}
if ($draftFile === null || !is_file($draftFile)) {
    usage();
}

$draft = json_decode((string)file_get_contents($draftFile), true);
if (!is_array($draft['signatures'] ?? null)) {
    fwrite(STDERR, "{$draftFile} must contain a top-level \"signatures\" array\n");
    exit(2);
}

$sourceLines = [];
if ($sourceFile !== null) {
    $sourceLines = array_values(array_filter(array_map('trim', explode("\n", (string)file_get_contents($sourceFile))), 'strlen'));
}

$current = json_decode((string)file_get_contents(ROOT . '/signatures.json'), true);
$existingIds = array_column($current['signatures'], 'id');
$existingPatterns = array_column($current['signatures'], 'pattern');
$clean = listFilesRecursively(ROOT . '/corpus/clean');

/**
 * The literal runs a signature is built on: at least 10 characters, taken from the pattern with
 * regex metacharacters removed. Two signatures built on the same run are the same technique.
 *
 * @return list<string>
 */
function coreTokens(array $sig): array
{
    $pattern = (string)($sig['pattern'] ?? '');
    if (($sig['pattern_type'] ?? '') === 'regex') {
        $pattern = preg_replace('#^/(.*)/[a-z]*$#s', '$1', $pattern) ?? $pattern;
        $pattern = preg_replace('/\\\\./s', ' ', $pattern) ?? $pattern;
    }
    $parts = preg_split('/[\[\]\(\)\|\*\+\?\{\}\^\$\.\\\\]+/', $pattern) ?: [];

    // A bare identifier such as base64_decode is a common function name, not a technique, so it only
    // counts when it has punctuation or spaces, or is long enough to be specific on its own.
    return array_values(array_filter(
        array_map('trim', $parts),
        static fn (string $t): bool => mb_strlen($t) >= 10 && (preg_match('/[^A-Za-z0-9_]/', $t) === 1 || mb_strlen($t) >= 20)
    ));
}

/**
 * The existing signature whose core literal overlaps one of this signature's, or null.
 *
 * @param list<array<string, mixed>> $existing
 */
function conceptOverlap(array $sig, array $existing): ?string
{
    $mine = coreTokens($sig);
    foreach ($existing as $other) {
        foreach (coreTokens($other) as $theirs) {
            foreach ($mine as $token) {
                if (str_contains($theirs, $token) || str_contains($token, $theirs)) {
                    return "{$other['id']} (shares \"{$token}\")";
                }
            }
        }
    }

    return null;
}

$accepted = [];
$rejected = 0;
foreach ($draft['signatures'] as $sig) {
    $id = (string)($sig['id'] ?? '');
    $problems = [];

    if (in_array($id, $existingIds, true) || in_array($id, array_column($accepted, 'id'), true)) {
        $problems[] = 'duplicate id';
    }
    if (in_array($sig['pattern'] ?? null, $existingPatterns, true)) {
        $problems[] = 'same pattern already in signatures.json';
    }
    $problems = array_merge($problems, validateSignatureSet([$sig], $clean));

    if (($sig['pattern_type'] ?? '') === 'literal') {
        $pat = (string)($sig['pattern'] ?? '');
        if (preg_match('#^[\w.\-]+(/[\w.\-]*)+/?$#', $pat) === 1) {
            $problems[] = 'pattern is a file path, not content a scanner can match inside a file';
        }
        if (preg_match('/^[\w\-]+\.(?:php|phtml|phar)$/i', $pat) === 1) {
            $problems[] = 'pattern is a bare file name, which matches any file that mentions it';
        }
    }

    $overlap = conceptOverlap($sig, [...$current['signatures'], ...$accepted]);
    if ($overlap !== null) {
        $problems[] = 'same technique as existing signature ' . $overlap;
    }

    if ($sourceLines !== []) {
        $matchesSource = false;
        foreach ($sourceLines as $line) {
            if (signatureMatches($sig, $line)) {
                $matchesSource = true;
                break;
            }
        }
        if (!$matchesSource) {
            $problems[] = 'does not match any line of the source text';
        }
    }

    if ($problems === []) {
        $accepted[] = $sig;
        echo "OK      {$id}\n";
    } else {
        $rejected++;
        echo "REJECT  {$id}: " . implode('; ', $problems) . "\n";
    }
}

echo "\n" . count($accepted) . ' accepted, ' . $rejected . " rejected\n";

$coreAccepted = array_values(array_filter($accepted, fn (array $x): bool => empty($x['ioc'])));
$iocAccepted = array_values(array_filter($accepted, fn (array $x): bool => !empty($x['ioc'])));

if ($apply && $iocAccepted !== []) {
    $iocPath = ROOT . '/ioc/indicators.json';
    $ioc = is_file($iocPath) ? json_decode((string)file_get_contents($iocPath), true) : ['signatures' => []];
    $expires = date('Y-m-d', strtotime('+180 days'));
    foreach ($iocAccepted as $x) {
        $x['expires_on'] = $expires;
        $ioc['signatures'][] = $x;
    }
    $ioc['version'] = date('Y.m.d');
    if (!is_dir(dirname($iocPath))) {
        mkdir(dirname($iocPath), 0777, true);
    }
    file_put_contents($iocPath, json_encode($ioc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    echo count($iocAccepted) . " IOC signature(s) added to ioc/indicators.json, expiring {$expires}.\n";
}

if ($apply && $coreAccepted !== []) {
    $accepted = $coreAccepted;
    $current['signatures'] = [...$current['signatures'], ...$accepted];
    $current['version'] = date('Y.m.d');
    file_put_contents(ROOT . '/signatures.json', json_encode($current, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
    echo "Added to signatures.json (version {$current['version']}).\n";
} elseif (!$apply) {
    echo "Not applied. Re-run with --apply to add the accepted signatures.\n";
}

exit($accepted === [] && $draft['signatures'] !== [] ? 1 : 0);
