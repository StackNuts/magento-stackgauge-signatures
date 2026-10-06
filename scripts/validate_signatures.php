<?php
/**
 * CLI entry point for the CI gate: validates every signature in signatures.json via
 * lib/matching.php's validateSignatureSet(). See that file for what is checked.
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

$iocPath = __DIR__ . '/../ioc/indicators.json';
if (is_file($iocPath)) {
    $ioc = json_decode((string)file_get_contents($iocPath), true);
    $iocErrors = validateSignatureSet($ioc['signatures'] ?? [], listFilesRecursively($cleanCorpusDir));
    if ($iocErrors !== []) {
        fwrite(STDERR, count($iocErrors) . " IOC validation failure(s):\n");
        foreach ($iocErrors as $error) {
            fwrite(STDERR, "  - {$error}\n");
        }
        exit(1);
    }
    $expired = array_filter($ioc['signatures'] ?? [], fn (array $x): bool => ($x['expires_on'] ?? '9999-12-31') < date('Y-m-d'));
    if ($expired !== []) {
        echo count($expired) . " IOC entr(ies) past expires_on; re-check or remove: " . implode(', ', array_column($expired, 'id')) . "\n";
    }
}

echo "All signatures passed validation.\n";
exit(0);
