<?php
/**
 * Signature matching and vetting, used by validate_signatures.php (the CI gate). Pure functions with
 * no top-level script behaviour, so the same checks can be called from tests as well.
 */

declare(strict_types=1);

const ALLOWED_SEVERITIES = ['critical', 'warning'];
const ALLOWED_PATTERN_TYPES = ['literal', 'regex'];
const REQUIRED_FIELDS = ['id', 'name', 'severity', 'target', 'pattern_type', 'pattern', 'description'];

/**
 * Mirrors StackNuts\StackGaugeSecurity\Model\Util\ContentSignatureScanner::matches() exactly -
 * this is only meaningful as a vetting gate if it checks matching the same way the real
 * scanner does.
 */
function signatureMatches(array $signature, string $content): bool
{
    return match ($signature['pattern_type'] ?? null) {
        'literal' => str_contains($content, $signature['pattern']),
        'regex' => preg_match($signature['pattern'], $content) === 1,
        default => false,
    };
}

/**
 * @return list<string> Absolute paths of every file under $dir.
 */
function listFilesRecursively(string $dir): array
{
    if (!is_dir($dir)) {
        return [];
    }

    $files = [];
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
    foreach ($iterator as $fileInfo) {
        if ($fileInfo->isFile()) {
            $files[] = $fileInfo->getPathname();
        }
    }

    return $files;
}

/**
 * Validates every signature in $signatures (one, or the whole file's worth) against:
 * required fields, allowed severity/pattern_type values, duplicate ids within the set, regex
 * compilation, its own test_should_match/test_should_not_match samples, and - independently of
 * whatever samples the signature's own author wrote - every file in $existingCleanFiles.
 *
 * @param list<array<string, mixed>> $signatures
 * @param list<string> $existingCleanFiles Absolute paths, pre-loaded via listFilesRecursively().
 * @return list<string> Empty if every signature passed.
 */
function validateSignatureSet(array $signatures, array $existingCleanFiles): array
{
    $errors = [];
    $cleanContents = array_map('file_get_contents', $existingCleanFiles);

    $seenIds = [];
    foreach ($signatures as $index => $signature) {
        $label = is_array($signature) && isset($signature['id']) ? $signature['id'] : "index {$index}";

        foreach (REQUIRED_FIELDS as $field) {
            if (!isset($signature[$field])) {
                $errors[] = "{$label}: missing required field \"{$field}\"";
            }
        }
        if (!isset($signature['id'])) {
            continue;
        }

        if (isset($seenIds[$signature['id']])) {
            $errors[] = "{$label}: duplicate id";
        }
        $seenIds[$signature['id']] = true;

        if (isset($signature['severity']) && !in_array($signature['severity'], ALLOWED_SEVERITIES, true)) {
            $errors[] = "{$label}: severity \"{$signature['severity']}\" is not one of: "
                . implode(', ', ALLOWED_SEVERITIES);
        }

        if (isset($signature['pattern_type']) && !in_array($signature['pattern_type'], ALLOWED_PATTERN_TYPES, true)) {
            $errors[] = "{$label}: pattern_type \"{$signature['pattern_type']}\" is not one of: "
                . implode(', ', ALLOWED_PATTERN_TYPES);
        }

        if (!isset($signature['target']) || !is_array($signature['target']) || $signature['target'] === []) {
            $errors[] = "{$label}: \"target\" must be a non-empty array of strings";
        }

        if (!isset($signature['pattern']) || !isset($signature['pattern_type'])) {
            continue;
        }

        if ($signature['pattern_type'] === 'regex' && @preg_match($signature['pattern'], '') === false) {
            $errors[] = "{$label}: pattern does not compile as a valid regex";
            continue;
        }

        foreach ($signature['test_should_match'] ?? [] as $sampleIndex => $sample) {
            if (!signatureMatches($signature, $sample)) {
                $errors[] = "{$label}: test_should_match[{$sampleIndex}] did not match its own pattern";
            }
        }

        foreach ($signature['test_should_not_match'] ?? [] as $sampleIndex => $sample) {
            if (signatureMatches($signature, $sample)) {
                $errors[] = "{$label}: test_should_not_match[{$sampleIndex}] incorrectly matched";
            }
        }

        foreach ($existingCleanFiles as $fileIndex => $cleanFile) {
            if (signatureMatches($signature, $cleanContents[$fileIndex])) {
                $errors[] = "{$label}: matches corpus/clean/" . basename($cleanFile)
                    . " - false positive against known-benign content";
            }
        }
    }

    return $errors;
}
