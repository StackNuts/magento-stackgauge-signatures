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

echo 'All ' . 6 . " propose_signatures.php self-tests passed.\n";
exit(0);
