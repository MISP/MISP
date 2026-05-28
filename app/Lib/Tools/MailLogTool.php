<?php

declare(strict_types=1);

/**
 * MailLogTool — OS-level mail-log tail reader for MispMailLogWidget
 * (DD-41).
 *
 * Reads the last `$lookbackBytes` of a postfix-format log file, parses
 * the per-recipient delivery lines (those carrying `status=...`), and
 * returns the latest N normalised rows, newest-first.  Bounded read
 * (fseek -N from end-of-file) so the parser stays O(lookback) and
 * doesn't load multi-MB rotated logs into memory.
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
 * production default is `/var/log/mail.log`.
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
