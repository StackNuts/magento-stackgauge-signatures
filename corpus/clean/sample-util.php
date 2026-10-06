<?php
declare(strict_types=1);

/**
 * A representative "looks suspicious at a glance but isn't" sample - legitimate code that
 * uses base64/gzinflate utility functions for an unremarkable reason (decompressing a cached
 * payload), never combined with eval() or any request superglobal, and never named after a
 * known webshell family. Every signature in signatures.json must score zero matches here.
 */
final class CacheReader
{
    public function readCompressedCache(string $path): string
    {
        $raw = file_get_contents($path);
        $decompressed = gzinflate($raw);

        return base64_decode($decompressed) ?: '';
    }

    public function logRequestSummary(array $post): void
    {
        // Deliberately does NOT pass $post into exec/system/assert - just logs field names.
        $fields = implode(',', array_keys($post));
        error_log('Received fields: ' . $fields);
    }

    public function runScheduledSystemCheck(): bool
    {
        // "system" appears here only as a plain word/method name, not the system() function
        // called with request input - should not trip webshell-exec-request.
        return $this->checkSystemHealth();
    }

    private function checkSystemHealth(): bool
    {
        return true;
    }
}
