<?php
/**
 * SHA-256 sidecar for signatures.json, read by StackGaugeSecurity's SignatureFeedFetcher. The
 * module refuses any feed whose body doesn't hash to the published value, so this file must be
 * regenerated in the same commit as every change to signatures.json. Written in sha256sum
 * format ("<hash>  signatures.json") so it can also be checked with `sha256sum -c`.
 */

declare(strict_types=1);

const CHECKSUM_FILE_NAME = 'signatures.json.sha256';

function writeChecksum(string $jsonPath): void
{
    $hash = hash_file('sha256', $jsonPath);
    if ($hash === false) {
        throw new RuntimeException("Could not hash {$jsonPath}");
    }

    file_put_contents(dirname($jsonPath) . '/' . CHECKSUM_FILE_NAME, $hash . '  ' . basename($jsonPath) . "\n");
}

function verifyChecksum(string $jsonPath): bool
{
    $sumPath = dirname($jsonPath) . '/' . CHECKSUM_FILE_NAME;
    $expected = is_file($sumPath) ? strtok((string)file_get_contents($sumPath), " \n") : false;

    return $expected !== false && hash_file('sha256', $jsonPath) === strtolower($expected);
}
