<?php
/**
 * Exercises propose_signatures.php's vetting/parsing logic with a canned, fake Workers AI
 * response - no network access or API keys needed. Covers: a good candidate gets
 * accepted and appended; a candidate reusing an existing id is rejected; a candidate that
 * false-positives against corpus/clean/ is rejected; prose/fences around the JSON are
 * tolerated; nothing is ever written to the real signatures.json (this works against a
 * temporary copy).
 *
 * Run: php scripts/test_propose_signatures.php
 */

declare(strict_types=1);

const PROPOSE_SIGNATURES_TESTING = true;

require __DIR__ . '/propose_signatures.php';

$failures = [];

function check(array &$failures, bool $condition, string $message): void
{
    if (!$condition) {
        $failures[] = $message;
    }
}

$cleanFiles = listFilesRecursively(__DIR__ . '/../corpus/clean');
$existing = [
    'version' => '2026.10.0',
    'signatures' => [
        ['id' => 'existing-sig', 'name' => 'Already here', 'severity' => 'critical'],
    ],
];

// 1. extractCandidates() tolerates prose/fences around the JSON object.
$wrapped = "Sure, here are the signatures:\n```json\n"
    . '{"signatures":[{"id":"test-1","pattern":"x"}]}' . "\n```\nLet me know if you need more.";
$extracted = extractCandidates($wrapped);
check($failures, count($extracted) === 1 && $extracted[0]['id'] === 'test-1', 'extractCandidates did not tolerate surrounding prose/fences');
check($failures, extractCandidates('no json here at all') === [], 'extractCandidates should return [] when there is no JSON object');

// 2. A well-formed, genuinely safe candidate is accepted and appended.
$goodCandidate = [
    'id' => 'test-good-signature',
    'name' => 'Test webshell marker',
    'severity' => 'critical',
    'target' => ['pub_php'],
    'pattern_type' => 'literal',
    'pattern' => 'totally-unique-test-webshell-marker-xyz',
    'description' => 'test fixture',
    'test_should_match' => ['<?php /* totally-unique-test-webshell-marker-xyz */ ?>'],
    'test_should_not_match' => ['<?php echo "hello"; ?>'],
];
$result = applyCandidates([$goodCandidate], $existing, $cleanFiles, 5);
check($failures, count($result['accepted']) === 1, 'a well-formed candidate should be accepted');
check($failures, $result['rejected'] === [], 'a well-formed candidate should not be rejected');
check($failures, count($result['existing']['signatures']) === 2, 'accepted candidate should be appended to the existing set');
check($failures, $result['existing']['version'] === date('Y-m-d'), 'version should be bumped to today on acceptance');

// 3. A candidate reusing an existing id is rejected, not appended - otherwise identical to
// the accepted candidate above, so this isolates the duplicate-id check specifically rather
// than failing validateSignatureSet() for an unrelated reason.
$duplicateCandidate = [...$goodCandidate, 'id' => 'existing-sig'];
$result = applyCandidates([$duplicateCandidate], $existing, $cleanFiles, 5);
check($failures, $result['accepted'] === [], 'a duplicate id should not be accepted');
check($failures, isset($result['rejected']['existing-sig']), 'a duplicate id should be reported as rejected');

// 4. A candidate that false-positives against corpus/clean/ is rejected.
$falsePositiveCandidate = [
    'id' => 'test-too-broad',
    'name' => 'Too broad',
    'severity' => 'critical',
    'target' => ['cms_content'],
    'pattern_type' => 'literal',
    'pattern' => '<script',
    'description' => 'test fixture',
    'test_should_match' => ['<script>bad</script>'],
];
$result = applyCandidates([$falsePositiveCandidate], $existing, $cleanFiles, 5);
check($failures, $result['accepted'] === [], 'a candidate matching corpus/clean/ should not be accepted');
check($failures, isset($result['rejected']['test-too-broad']), 'a candidate matching corpus/clean/ should be reported as rejected');

// 5. maxNew caps how many candidates are even considered.
$manyCandidates = array_map(
    static fn (int $i): array => [
        'id' => "test-many-{$i}",
        'name' => 'n',
        'severity' => 'critical',
        'target' => ['pub_php'],
        'pattern_type' => 'literal',
        'pattern' => "unique-test-marker-{$i}",
        'description' => 'test fixture',
        'test_should_match' => ["unique-test-marker-{$i}"],
    ],
    range(1, 10)
);
$result = applyCandidates($manyCandidates, $existing, $cleanFiles, 3);
check($failures, count($result['accepted']) === 3, 'maxNew should cap how many candidates are accepted');


// Models write regex escapes such as \. straight into JSON. The repair must recover them.
$escaped = extractCandidates('{"signatures":[{"id":"esc-test","name":"n","severity":"critical","target":["pub_php"],"pattern_type":"regex","pattern":"/a\.b\-c/","description":"d","test_should_match":["x"],"test_should_not_match":["y"]}]}');
check($failures, count($escaped) === 1 && ($escaped[0]['pattern'] ?? '') === '/a\.b\-c/', 'extractCandidates should repair invalid JSON escapes such as \. and \-');

// 5a. Processed-source state: each source is read once; rejections persist until the rules change.
$stateSources = [
    'https://already-read.example' => ['url' => 'https://already-read.example', 'title' => 't', 'content' => 'c'],
    'https://never-read.example' => ['url' => 'https://never-read.example', 'title' => 't', 'content' => 'c'],
];
$stateFixture = [
    'rules_version' => PIPELINE_RULES_VERSION,
    'sources' => ['https://already-read.example' => ['first_seen' => '2026-06-01', 'outcome' => 'read']],
    'rejected' => ['known-bad' => ['reason' => 'x', 'date' => '2026-10-04']],
];
$fresh = excludeAlreadyRead($stateSources, $stateFixture);
check($failures, !isset($fresh['https://already-read.example']), 'a source already read should be skipped, however long ago');
check($failures, isset($fresh['https://never-read.example']), 'an unseen source should be considered');
check($failures, isRecentlyRejected('known-bad', $stateFixture), 'a rejection under the current rules should be skipped');
check($failures, !isRecentlyRejected('unknown-id', $stateFixture), 'an unknown candidate should not be skipped');

$tmpState = sys_get_temp_dir() . '/propose-state-test-' . getmypid() . '.json';
file_put_contents($tmpState, json_encode(['rules_version' => 'old-rules', 'sources' => [], 'rejected' => ['stale' => ['reason' => 'x', 'date' => '2026-01-01']]]));
$loaded = loadState($tmpState);
check($failures, $loaded['rejected'] === [], 'rejections from an older rules version should be cleared on load');
file_put_contents($tmpState, json_encode(['rules_version' => PIPELINE_RULES_VERSION, 'sources' => [], 'rejected' => ['kept' => ['reason' => 'x', 'date' => '2026-10-05']]]));
check($failures, isset(loadState($tmpState)['rejected']['kept']), 'rejections under the current rules should be kept on load');
unlink($tmpState);

// 5b. Grounding and shape checks reject weak candidates, and keep grounded ones.
$groundSource = normalizeForMatch('Attackers write eval(base64_decode($_POST["x"])) into pub/media files.');
$weak = [
    'path-literal' => ['pattern_type' => 'literal', 'pattern' => 'pub/media/custom_options/quote/', 'test_should_match' => ['pub/media/custom_options/quote/'], 'test_should_not_match' => ['pub/media/catalog/']],
    'char-class-alternation' => ['pattern_type' => 'regex', 'pattern' => '/process [kworker|fc-cache]/', 'test_should_match' => ['process kworker'], 'test_should_not_match' => ['process list']],
    'ungrounded' => ['pattern_type' => 'literal', 'pattern' => 'zzz-never-in-any-source-qqq', 'test_should_match' => ['zzz-never-in-any-source-qqq'], 'test_should_not_match' => ['harmless text']],
];
$weakSet = [];
foreach ($weak as $name => $parts) {
    $weakSet[] = array_merge(['id' => "weak-{$name}", 'name' => 'n', 'severity' => 'critical', 'target' => ['pub_php'], 'description' => 'd'], $parts);
}
$weakResult = applyCandidates($weakSet, $existing, $cleanFiles, 10, $groundSource);
check($failures, count($weakResult['accepted']) === 0, 'weak candidates must not be accepted');
check($failures, count($weakResult['rejected']) === 3, 'all three weak candidates should be rejected');
check($failures, str_contains($weakResult['rejected']['weak-path-literal'][0] ?? '', 'file path'), 'path literal should be rejected as a file path');
check($failures, str_contains($weakResult['rejected']['weak-char-class-alternation'][0] ?? '', 'character class'), 'alternation in a character class should be rejected');
check($failures, str_contains($weakResult['rejected']['weak-ungrounded'][0] ?? '', 'does not appear'), 'a pattern absent from the sources should be rejected');

$groundedResult = applyCandidates([[
    'id' => 'grounded-eval', 'name' => 'n', 'severity' => 'critical', 'target' => ['pub_php'], 'description' => 'd',
    'pattern_type' => 'literal', 'pattern' => 'eval(base64_decode(',
    'test_should_match' => ['<?php eval(base64_decode($x)); ?>'], 'test_should_not_match' => ['<?php echo 1; ?>'],
]], $existing, $cleanFiles, 10, $groundSource);
check($failures, count($groundedResult['accepted']) === 1, 'a pattern present in the sources should be accepted');

$proseResult = applyCandidates([['id' => 'prose-marker', 'name' => 'n', 'severity' => 'critical', 'target' => ['cms_content'], 'description' => 'd', 'pattern_type' => 'regex', 'pattern' => '/API authorization token|secret Magento cryptographic keys/', 'test_should_match' => ['API authorization token'], 'test_should_not_match' => ['harmless text']]], $existing, $cleanFiles, 10, normalizeForMatch('the API authorization token and secret Magento cryptographic keys'));
check($failures, str_contains($proseResult['rejected']['prose-marker'][0] ?? '', 'plain English prose'), 'plain-English patterns should be rejected as prose');

check($failures, longestRegexLiteral('/eval\s*\(\s*base64_decode\s*\(/i') === 'base64_decode', 'longestRegexLiteral should return the longest literal run');
check($failures, explainEmptyReply('') === 'the model returned an empty reply', 'explainEmptyReply should report an empty reply');
check($failures, explainEmptyReply('no braces') === 'the reply contains no JSON object', 'explainEmptyReply should report a missing JSON object');
check($failures, str_contains(explainEmptyReply('{"signatures": []}'), 'empty'), 'explainEmptyReply should report an empty signatures array');
// 6. buildPrBody() mentions both accepted and rejected entries.
$prBody = buildPrBody(
    [['id' => 'a', 'severity' => 'critical', 'description' => 'd']],
    ['b' => ['some reason']],
    '@cf/meta/llama-3.3-70b-instruct-fp8-fast'
);
check($failures, str_contains($prBody, 'a'), 'PR body should mention the accepted id');
check($failures, str_contains($prBody, 'some reason'), 'PR body should mention the rejection reason');

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " test failure(s):\n");
    foreach ($failures as $failure) {
        fwrite(STDERR, "  - {$failure}\n");
    }
    exit(1);
}

echo 'All ' . 10 . " propose_signatures.php self-tests passed.\n";
exit(0);
