<?php
/**
 * CLI entry point for the CI gate: validates every signature in signatures.json via
 * lib/matching.php's validateSignatureSet() - the same function propose_signatures.php uses to
 * vet one candidate before it's ever written to the file. See that file's own docblock for
 * what's actually being checked.
 *
 * Usage: php scripts/validate_signatures.php [path/to/signatures.json] [path/to/corpus/clean]
 */

declare(strict_types=1);

require __DIR__ . '/lib/matching.php';

$signaturesPath = $argv[1] ?? __DIR__ . '/../signatures.json';
$cleanCorpusDir = $argv[2] ?? __DIR__ . '/../corpus/clean';

$raw = @file_get_contents($signaturesPath);
if ($raw === false) {
    fwrite(STDERR, "Could not read {$signaturesPath}\n");
    exit(1);
}

$decoded = json_decode($raw, true);
if (!is_array($decoded) || !isset($decoded['signatures']) || !is_array($decoded['signatures'])) {
    fwrite(STDERR, "{$signaturesPath} is not valid JSON with a top-level \"signatures\" array\n");
    exit(1);
}

$errors = validateSignatureSet($decoded['signatures'], listFilesRecursively($cleanCorpusDir));

if ($errors !== []) {
    fwrite(STDERR, count($errors) . " validation failure(s):\n");
    foreach ($errors as $error) {
        fwrite(STDERR, "  - {$error}\n");
    }
    exit(1);
}

echo "All signatures passed validation.\n";
exit(0);
