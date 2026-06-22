<?php

declare(strict_types=1);

/**
 * MailLogTool — OS-level mail-log tail reader for MispMailLogWidget
 * (DD-41; rotated-file traversal added DD-43).
 *
 * Reads the last `$lookbackBytes` of a postfix-format log file, parses
 * the per-recipient delivery lines (those carrying `status=...`), and
 * returns the latest N normalised rows, newest-first.  Bounded read
 * (fseek -N from end-of-file) so the parser stays O(lookback) and
 * doesn't load multi-MB rotated logs into memory.
 *
 * **Rotated-file traversal (DD-43).** When `$search` is non-empty and
 * the live-tail returns fewer than `$limit` matching rows, the
 * remaining slots are filled by scanning rotated companions in age
 * order: `mail.log.1` (uncompressed), then `mail.log.N.gz` (gzip-
 * compressed) for N >= 2.  Each companion is path-validated
 * independently (allow-list + realpath); plain rotated files use the
 * same fseek tail as the live log, gzip-compressed files use a
 * streaming `gzopen`+`gzgets` forward scan with per-file array_reverse
 * to newest-first.  Age-ordered concatenation preserves globally
 * newest-first ordering across files; total cap at `$limit` rows.
 *
 * Per-row shape returned by tail():
 *   [
 *     'ts'        => 1716902447,                  // Unix seconds
 *     'recipient' => 'alice@example.com',         // to=<...>
 *     'status'    => 'sent',                      // one of:
 *                                                 //   sent | deferred |
 *                                                 //   bounced | expired |
 *                                                 //   undeliverable
 *     'message'   => '250 2.0.0 OK',              // status detail in
 *                                                 //   parens
 *     'relay'     => 'mail.example.com[1.2.3.4]:25',
 *     'queue_id'  => 'ABCD1234',
 *   ]
 *
 * Path safety — the configured path must match the allow-list
 * `^/(var/log|tmp)/[A-Za-z0-9._/-]+$`.  `/tmp/...` is permitted because
 * the verification recipes use a synthetic log fixture there; the
 * production default is `/var/log/mail.log`.  Each rotated companion
 * goes through the same allow-list + realpath check (a symlink under
 * `/var/log/` pointing at `/etc/shadow.1.gz` would be rejected).
 *
 * Failure modes:
 *   - InvalidArgumentException — path not in allow-list (config error).
 *   - RuntimeException         — file missing or unreadable (operator
 *                                hasn't set up `www-data` access yet).
 *   - Empty array              — readable but no parseable rows.
 *
 * The widget catches both exceptions and renders an empty-state
 * `message` row with an inline `<details>` setup-help block (DD-41).
 */
class MailLogTool
{
    public const DEFAULT_PATH          = '/var/log/mail.log';
    public const DEFAULT_LOOKBACK      = 65536;
    public const DEFAULT_LIMIT         = 20;
    private const PATH_ALLOWLIST_REGEX = '~^/(var/log|tmp)/[A-Za-z0-9._/-]+$~';
    private const RECOGNISED_STATUSES  = array(
        'sent', 'deferred', 'bounced', 'expired', 'undeliverable',
    );

    /**
     * Count log files available for scanning at $path: the live file
     * (if readable) + rotated companions (`<path>.1`, `<path>.N.gz`)
     * that pass the same per-file safety bundle.  Used by widgets to
     * adapt the empty-state text when rotated traversal happens
     * (DD-43).  Cheap — only stats files, doesn't open them.
     *
     * Returns 0 if the live file is unreadable (caller should already
     * have rendered the setup-recipe empty-state in that case).
     */
    public static function countLogFiles(string $path): int
    {
        if (!self::_isReadableAllowedFile($path)) {
            return 0;
        }
        $count = 1;
        foreach (self::_findRotated($path) as $rotated) {
            if (self::_isReadableAllowedFile($rotated['path'])) {
                $count++;
            }
        }
        return $count;
    }

    /**
     * Is the configured path in the allow-list?  Called by both the
     * widget (to decide which empty-state to render) and tail() itself.
     *
     * Two-layer check: (1) reject any `..` / NUL byte upfront so the
     * regex prefix `^/var/log/` can't be bypassed via traversal
     * (`/var/log/../etc/passwd`); (2) regex match the literal path
     * shape.  A post-existence realpath() check in tail() is the third
     * layer for symlink resolution once the file is known to exist.
     */
    public static function isAllowedPath(string $path): bool
    {
        if ($path === '' || strpos($path, '..') !== false || strpos($path, "\0") !== false) {
            return false;
        }
        return (bool)preg_match(self::PATH_ALLOWLIST_REGEX, $path);
    }

    /**
     * Tail-read + parse $path; return up to $limit rows, newest first.
     *
     * When $search is a non-empty string, each parsed row is filtered
     * by case-insensitive substring match against recipient, relay,
     * queue_id, and the MTA message — non-matching rows are skipped
     * BEFORE the limit cap, so $limit reflects matching rows, not
     * all rows in the window.  Caller can bump $lookbackBytes when
     * the filter is active to give the search range to work with.
     *
     * When $search is non-empty AND the live-tail returned fewer than
     * $limit matching rows, rotated companions (`<path>.1`,
     * `<path>.N.gz`) are scanned in age order to fill the remaining
     * slots (DD-43).  Without a search filter, only the live file is
     * read — there's no value in plowing through rotated history when
     * the operator just wants "the latest N events".
     */
    public static function tail(
        string $path,
        int $lookbackBytes = self::DEFAULT_LOOKBACK,
        int $limit = self::DEFAULT_LIMIT,
        string $search = ''
    ): array {
        if (!self::isAllowedPath($path)) {
            throw new InvalidArgumentException(
                'Mail-log path not in allow-list: ' . $path
            );
        }
        if (!is_file($path)) {
            throw new RuntimeException('Mail-log not found: ' . $path);
        }
        // Post-existence realpath check — a symlink under /var/log/
        // pointing at /etc/shadow would have passed the regex.
        $real = @realpath($path);
        if ($real === false || !self::isAllowedPath($real)) {
            throw new RuntimeException(
                'Mail-log resolved path not in allow-list: ' . $path
            );
        }
        if (!is_readable($path)) {
            throw new RuntimeException('Mail-log not readable: ' . $path);
        }
        $rows = self::_tailPlainFseek($path, $lookbackBytes, $limit, $search);

        // DD-43 — when the search filter is active and there's still
        // room in the result, fill remaining slots from rotated
        // companions (newest rotation first, then older).  Plain
        // `<path>.1` uses the same fseek tail; `<path>.N.gz` uses a
        // streaming forward scan via gzopen.  Each rotated file is
        // re-validated against the allow-list + realpath — an attacker
        // can't sneak `/etc/shadow.1` past the per-file safety check.
        if ($search !== '' && count($rows) < $limit) {
            foreach (self::_findRotated($path) as $rotated) {
                $remaining = $limit - count($rows);
                if ($remaining <= 0) {
                    break;
                }
                if (!self::_isReadableAllowedFile($rotated['path'])) {
                    continue;
                }
                if ($rotated['gzip']) {
                    $more = self::_scanForward(
                        $rotated['path'],
                        true,
                        $remaining,
                        $search
                    );
                } else {
                    $more = self::_tailPlainFseek(
                        $rotated['path'],
                        $lookbackBytes,
                        $remaining,
                        $search
                    );
                }
                if (!empty($more)) {
                    $rows = array_merge($rows, $more);
                }
            }
            if (count($rows) > $limit) {
                $rows = array_slice($rows, 0, $limit);
            }
        }
        return $rows;
    }

    /**
     * Bounded fseek tail of a plain (uncompressed) log file.  Caller is
     * responsible for path validation; this method assumes $path has
     * already been allow-listed and is readable.
     *
     * Returns rows newest-first, capped at $limit.
     */
    private static function _tailPlainFseek(
        string $path,
        int $lookbackBytes,
        int $limit,
        string $search
    ): array {
        $size = @filesize($path);
        if ($size === false) {
            throw new RuntimeException('Cannot stat mail-log: ' . $path);
        }
        if ($size === 0) {
            return array();
        }
        $fp = @fopen($path, 'rb');
        if (!$fp) {
            throw new RuntimeException('Cannot open mail-log: ' . $path);
        }
        $lookback = max(1024, $lookbackBytes);
        try {
            $start = max(0, $size - $lookback);
            if (@fseek($fp, $start) !== 0) {
                return array();
            }
            // Discard the (likely-truncated) first line unless we
            // started from byte 0.
            if ($start > 0) {
                @fgets($fp);
            }
            $rows = array();
            // Hard iteration cap so a malformed read can't loop unbounded.
            $maxIter = max(2048, intdiv($lookback, 64));
            $iter = 0;
            $needle = ($search !== '') ? $search : null;
            while (($line = fgets($fp)) !== false) {
                if (++$iter > $maxIter) {
                    break;
                }
                $row = self::parseLine(rtrim($line, "\r\n"));
                if ($row === null) {
                    continue;
                }
                if ($needle !== null) {
                    // Search across the four content fields of the
                    // normalised row.  Case-insensitive substring —
                    // good enough for "find all entries for alice@…"
                    // and avoids the false-positive surface of a
                    // regex over user-controlled input.
                    $haystack = $row['recipient'] . ' '
                        . $row['relay'] . ' '
                        . $row['queue_id'] . ' '
                        . $row['message'];
                    if (stripos($haystack, $needle) === false) {
                        continue;
                    }
                }
                $rows[] = $row;
            }
        } finally {
            fclose($fp);
        }
        // Newest first; cap to $limit.
        $rows = array_reverse($rows);
        if (count($rows) > $limit) {
            $rows = array_slice($rows, 0, $limit);
        }
        return $rows;
    }

    /**
     * Streaming forward scan of a (possibly gzip-compressed) log file
     * for a search-filtered subset (DD-43).  Used for rotated `.gz`
     * companions where fseek-tail isn't possible without decompressing
     * the whole file just to find its end.
     *
     * Reads chronologically, collects matching rows, then reverses to
     * newest-first and caps to $limit.  Memory bound is one row per
     * matching line in the file — proportional to filter selectivity,
     * not file size.  Hard iteration cap (10M lines) guards against a
     * pathologically large file.
     */
    private static function _scanForward(
        string $path,
        bool $isGzip,
        int $limit,
        string $search
    ): array {
        $fp = $isGzip ? @gzopen($path, 'rb') : @fopen($path, 'rb');
        if (!$fp) {
            return array();
        }
        $rows = array();
        $iter = 0;
        $maxIter = 10000000;
        $needle = ($search !== '') ? $search : null;
        try {
            while (true) {
                $line = $isGzip ? gzgets($fp) : fgets($fp);
                if ($line === false) {
                    break;
                }
                if (++$iter > $maxIter) {
                    break;
                }
                $row = self::parseLine(rtrim($line, "\r\n"));
                if ($row === null) {
                    continue;
                }
                if ($needle !== null) {
                    $haystack = $row['recipient'] . ' '
                        . $row['relay'] . ' '
                        . $row['queue_id'] . ' '
                        . $row['message'];
                    if (stripos($haystack, $needle) === false) {
                        continue;
                    }
                }
                $rows[] = $row;
            }
        } finally {
            if ($isGzip) {
                gzclose($fp);
            } else {
                fclose($fp);
            }
        }
        $rows = array_reverse($rows);
        if (count($rows) > $limit) {
            $rows = array_slice($rows, 0, $limit);
        }
        return $rows;
    }

    /**
     * Discover rotated companions of $path in age order (newest
     * rotation first).  Returns an array of `['path' => string,
     * 'gzip' => bool, 'rank' => int]` entries ordered by rank ASC
     * (rank 1 = `.1` = newest rotation, rank 7 = oldest typical
     * logrotate retention).
     *
     * Only numeric-suffix companions (with optional `.gz`) are
     * returned; arbitrary sibling files like `mail.log.bak` are
     * filtered out.  Glob errors return an empty array.
     */
    private static function _findRotated(string $path): array
    {
        $candidates = @glob($path . '.*');
        if ($candidates === false || empty($candidates)) {
            return array();
        }
        $entries = array();
        $prefixLen = strlen($path) + 1;
        foreach ($candidates as $candidate) {
            $suffix = substr($candidate, $prefixLen);
            $isGzip = false;
            if (substr($suffix, -3) === '.gz') {
                $isGzip = true;
                $suffix = substr($suffix, 0, -3);
            }
            if ($suffix === '' || !ctype_digit($suffix)) {
                continue;
            }
            $entries[] = array(
                'path' => $candidate,
                'gzip' => $isGzip,
                'rank' => (int)$suffix,
            );
        }
        usort($entries, function ($a, $b) {
            return $a['rank'] - $b['rank'];
        });
        return $entries;
    }

    /**
     * Per-rotated-file safety bundle: allow-list shape check, file-
     * existence, realpath re-validation, readability.  Silent on
     * failure (rotated files are best-effort fill; missing or
     * unreadable companions are skipped, not fatal).
     */
    private static function _isReadableAllowedFile(string $path): bool
    {
        if (!self::isAllowedPath($path)) {
            return false;
        }
        if (!is_file($path)) {
            return false;
        }
        $real = @realpath($path);
        if ($real === false || !self::isAllowedPath($real)) {
            return false;
        }
        if (!is_readable($path)) {
            return false;
        }
        return true;
    }

    /**
     * Parse a single postfix log line — returns null when the line is
     * not a parseable per-recipient delivery record (queue lifecycle,
     * other daemons, malformed, etc.).
     */
    private static function parseLine(string $line): ?array
    {
        // Two timestamp shapes both seen on Debian/Ubuntu, depending on
        // the rsyslog version: ISO-ish RFC3339 (modern default) and
        // legacy 3-token syslog ("May 28 15:40:47").  Match either.
        //
        // Filter to postfix delivery processes that actually emit
        // `status=...`: smtp / lmtp / local / virtual / error / bounce.
        // Other postfix processes (pickup, cleanup, qmgr, master,
        // postfix-script, …) don't carry a delivery verdict; they go
        // through parseLine() unmatched and are skipped.
        $patterns = array(
            // RFC3339:   2026-05-28T15:40:47.383455+02:00 host postfix/smtp[N]: QID: rest
            '/^(?P<ts>\S+T\S+)\s+\S+\s+postfix\/(?P<proc>smtp|lmtp|local|virtual|error|bounce)'
            . '\[\d+\]:\s+(?P<qid>[A-F0-9]+):\s+(?P<rest>.+)$/',
            // Legacy:    May 28 15:40:47 host postfix/smtp[N]: QID: rest
            '/^(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+postfix\/'
            . '(?P<proc>smtp|lmtp|local|virtual|error|bounce)\[\d+\]:'
            . '\s+(?P<qid>[A-F0-9]+):\s+(?P<rest>.+)$/',
        );
        $matched = null;
        foreach ($patterns as $pat) {
            if (preg_match($pat, $line, $m)) {
                $matched = $m;
                break;
            }
        }
        if ($matched === null) {
            return null;
        }
        $rest = $matched['rest'];
        // Must carry `status=<word>` to be a delivery record.
        if (!preg_match('/\bstatus=(\w+)(?:\s+\(([^)]*)\))?/', $rest, $sm)) {
            return null;
        }
        $status = strtolower($sm[1]);
        if (!in_array($status, self::RECOGNISED_STATUSES, true)) {
            return null;
        }
        $recipient = '';
        if (preg_match('/\bto=<([^>]*)>/', $rest, $tm)) {
            $recipient = $tm[1];
        }
        $relay = '';
        if (preg_match('/\brelay=([^,]+)/', $rest, $rm)) {
            $relay = trim($rm[1]);
        }
        $ts = @strtotime($matched['ts']);
        return array(
            'ts'        => $ts === false ? 0 : (int)$ts,
            'recipient' => $recipient,
            'status'    => $status,
            'message'   => isset($sm[2]) ? $sm[2] : '',
            'relay'     => $relay,
            'queue_id'  => $matched['qid'],
        );
    }
}
