<?php
/**
 * CLI for the signatures.json checksum. `write` regenerates it (run by check_draft.php --apply);
 * `verify` exits non-zero if it doesn't match (run by validate.yml on every push and PR).
 *
 * Usage: php scripts/checksum.php write|verify
 */

declare(strict_types=1);

require __DIR__ . '/lib/checksum.php';

$json = __DIR__ . '/../signatures.json';

switch ($argv[1] ?? '') {
    case 'write':
        writeChecksum($json);
        echo "Wrote " . CHECKSUM_FILE_NAME . "\n";
        exit(0);
    case 'verify':
        if (verifyChecksum($json)) {
            echo "Checksum matches signatures.json.\n";
            exit(0);
        }
        fwrite(STDERR, CHECKSUM_FILE_NAME . " is missing or does not match signatures.json. Run: php scripts/checksum.php write\n");
        exit(1);
    default:
        fwrite(STDERR, "Usage: php scripts/checksum.php write|verify\n");
        exit(2);
}
