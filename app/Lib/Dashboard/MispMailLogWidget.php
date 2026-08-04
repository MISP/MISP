<?php

App::uses('MailLogTool', 'Tools');

/**
 * MISP Mail Log — outgoing-mail status tail (DD-41).
 *
 * Reads the last N postfix-format delivery records from the OS mail
 * log (default `/var/log/mail.log`) via `MailLogTool` and renders them
 * as UserList rows with a status-tinted glyph per row (DD-41
 * extension): green check (sent), amber triangle (deferred), red
 * circle-X (bounced / expired / undeliverable).
 *
 * Why the OS log and not the MISP audit log: `logs.action='email'` only
 * records *successful* sends from MISP's side — it never sees the
 * upstream MTA verdict.  A `250 OK` from the local postfix is logged as
 * success even when the message later bounces upstream.  The OS log is
 * the only source that captures **remote bounces**, which are the
 * primary signal admins want here.
 *
 * Access constraint: `/var/log/mail.log` is `640 syslog:adm` on
 * Debian/Ubuntu; `www-data` is not in `adm` by default.  Adding it
 * would grant read on most of `/var/log/*` — a meaningful production-
 * fleet privilege expansion (user-rejected).  Chosen path: configurable
 * path + clear empty-state with inline `<details>` setup-help when the
 * file is unreadable.  Operator picks their preferred access strategy
 * (adm membership, dedicated rsyslog tee under `/var/log/misp/`, or a
 * POSIX ACL).  Path is restricted to an allow-list pattern in
 * `MailLogTool::isAllowedPath()` so a config mistake can't turn the
 * widget into a generic file viewer.
 *
 * Site-admin only (it exposes recipient addresses).
 */
class MispMailLogWidget
{
    public $title = 'MISP Mail Log';
    public $category = 'system';
    // UserList render kind (DD-35) with the DD-41 glyph slot.
    public $render = 'UserList';
    public $width = 4;
    public $height = 5;
    public $params = array(
        'log_path' => 'OS mail log path (default /var/log/mail.log).',
        'limit' => 'Maximum rows to display (default 20).',
        'lookback_bytes' => 'Tail-read window in bytes (default 65536, larger 1MB default when "search" is set).',
        'search' => 'Case-insensitive substring filter applied to recipient, relay, queue ID, and the MTA message. Empty = no filter (default).',
    );
    public $schema = array(
        'log_path' => array('type' => 'string'),
        'limit' => array('type' => 'integer'),
        'lookback_bytes' => array('type' => 'integer'),
        'search' => array('type' => 'string'),
    );
    public $placeholder = '{
  "log_path": "/var/log/mail.log",
  "limit": 20,
  "lookback_bytes": 65536,
  "search": ""
}';
    public $description = 'Recent outgoing mail with the upstream MTA verdict (sent / deferred / bounced / expired). Reads the OS mail log; operator must grant www-data read access.';
    // Bursty signal — polling every 60s catches a just-bounced row
    // promptly while the per-render tail-read stays cheap.
    public $autoRefreshDelay = 60;
    // Anti-thundering-herd cache only; tail-reading 64 KB is cheap.
    public $cache_duration = 30;

    public function handler($user, $options = array())
    {
        $config = is_array($options) ? $options : array();

        $path = isset($config['log_path']) && is_string($config['log_path']) && $config['log_path'] !== ''
            ? $config['log_path']
            : MailLogTool::DEFAULT_PATH;
        $limit = isset($config['limit']) ? (int)$config['limit'] : MailLogTool::DEFAULT_LIMIT;
        if ($limit < 1) {
            $limit = MailLogTool::DEFAULT_LIMIT;
        }
        if ($limit > 200) {
            $limit = 200;
        }
        $search = isset($config['search']) && is_string($config['search'])
            ? trim($config['search'])
            : '';
        // When a search filter is active, default lookback bumps to
        // 1 MB so the filter has actual range to scan (the default
        // 64 KB tail is too small to find anything older than a few
        // hours on a busy box).  Operator can override either way
        // via the explicit `lookback_bytes` config.
        $defaultLookback = $search !== ''
            ? 1024 * 1024
            : MailLogTool::DEFAULT_LOOKBACK;
        $lookback = isset($config['lookback_bytes']) ? (int)$config['lookback_bytes'] : $defaultLookback;
        if ($lookback < 1024) {
            $lookback = $defaultLookback;
        }
        if ($lookback > 4 * 1024 * 1024) {
            $lookback = 4 * 1024 * 1024;
        }

        try {
            $rows = MailLogTool::tail($path, $lookback, $limit, $search);
        } catch (InvalidArgumentException $e) {
            return $this->_errorRow(
                __('Log path not in allow-list'),
                $path,
                array(
                    __('Path must match /var/log/... or /tmp/...'),
                    __('Edit the widget config or MISP.mail_log_path to a permitted location.'),
                )
            );
        } catch (RuntimeException $e) {
            // The expected default-install state: postfix logs to
            // /var/log/mail.log mode 640 syslog:adm; www-data isn't in
            // adm.  Surface the setup recipe so the operator knows
            // exactly what to do.
            return $this->_errorRow(
                __('Mail log not accessible'),
                $path,
                $this->_setupRecipe()
            );
        }

        if (empty($rows)) {
            if ($search !== '') {
                // DD-43 — when rotated companions exist, the search
                // traversed live + rotated logs; the "last X bytes of
                // log" phrasing would understate the scan.
                $fileCount = MailLogTool::countLogFiles($path);
                $emptyMsg = $fileCount > 1
                    ? sprintf(
                        __n(
                            'No matches for "%s" across %d log file',
                            'No matches for "%s" across %d log files',
                            $fileCount
                        ),
                        $search,
                        $fileCount
                    )
                    : sprintf(
                        __('No matches for "%s" in the last %s of log'),
                        $search,
                        $this->_humanizeBytes($lookback)
                    );
            } else {
                $emptyMsg = sprintf(
                    __('No recent mail events in the last %s'),
                    $this->_humanizeBytes($lookback)
                );
            }
            return array(array(
                'type' => 'header',
                'value' => $emptyMsg,
            ));
        }

        return $this->_buildRows($rows, $path, $search);
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }

    // ----------------------------------------------------------------

    /**
     * Build the UserList row list from parsed mail-log rows.  Header
     * carries a per-status tally; each row is a glyph + recipient +
     * status·age·relay·message meta line + chip-style status badge.
     */
    private function _buildRows(array $rows, $path, $search = '')
    {
        $tally = array(
            'sent' => 0, 'deferred' => 0, 'bounced' => 0,
            'expired' => 0, 'undeliverable' => 0,
        );
        foreach ($rows as $r) {
            if (isset($tally[$r['status']])) {
                $tally[$r['status']]++;
            }
        }
        $headerParts = array();
        foreach ($tally as $status => $count) {
            if ($count > 0) {
                $headerParts[] = sprintf('%d %s', $count, $this->_statusLabel($status));
            }
        }
        // When the filter is active, the header announces it as a
        // "N matches for '<term>' · <per-status tally>" so the operator
        // doesn't mistake a filtered tail for a global one.
        if ($search !== '') {
            $headerValue = sprintf(
                __n('%d match for "%s"', '%d matches for "%s"', count($rows)),
                count($rows),
                $search
            );
            if (!empty($headerParts)) {
                $headerValue .= ' · ' . implode(' · ', $headerParts);
            }
        } else {
            $headerValue = sprintf(
                __n('%d event · %s', '%d events · %s', count($rows)),
                count($rows),
                $headerParts ? implode(' · ', $headerParts) : ''
            );
        }

        $now = time();
        $out = array(array(
            'type' => 'header',
            'value' => trim($headerValue),
        ));
        foreach ($rows as $r) {
            $statusLabel = $this->_statusLabel($r['status']);
            $age = max(0, $now - (int)$r['ts']);
            $metaParts = array(
                $statusLabel,
                $this->_humanizeAge($age) . ' ' . __('ago'),
            );
            if (!empty($r['relay']) && $r['relay'] !== 'none') {
                $metaParts[] = 'relay=' . $r['relay'];
            }
            if (!empty($r['message'])) {
                $metaParts[] = $this->_truncate($r['message'], 80);
            }
            $out[] = array(
                'type' => 'user',
                'glyph' => $this->_statusGlyph($r['status']),
                'name' => $r['recipient'] !== '' ? $r['recipient'] : __('(no recipient)'),
                'meta' => implode(' · ', $metaParts),
                'badge' => $statusLabel,
            );
        }
        return $out;
    }

    /**
     * Status → glyph-token map (the DD-41 UserList extension).
     */
    private function _statusGlyph($status)
    {
        switch ($status) {
            case 'sent':          return 'check';
            case 'deferred':      return 'warn';
            case 'bounced':       return 'danger';
            case 'expired':       return 'danger';
            case 'undeliverable': return 'danger';
            default:              return 'info';
        }
    }

    private function _statusLabel($status)
    {
        switch ($status) {
            case 'sent':          return __('Sent');
            case 'deferred':      return __('Deferred');
            case 'bounced':       return __('Bounced');
            case 'expired':       return __('Expired');
            case 'undeliverable': return __('Undeliverable');
            default:              return ucfirst($status);
        }
    }

    private function _errorRow($title, $path, array $recipe)
    {
        return array(array(
            'type' => 'message',
            'title' => $title,
            'value' => $path,
            'recipe' => $recipe,
        ));
    }

    /**
     * Operator setup recipe — the single recommended strategy for
     * granting www-data read access to /var/log/mail.log (DD-41).
     * Inline `<details>` block on the empty-state row.
     *
     * Returned verbatim as a shell snippet; the snippet's own comments
     * carry the explanation (the inner $FileCreateMode 0640 reset is
     * load-bearing — without it the 0644 mode leaks to every
     * subsequent rsyslog-created file).  The renderer treats a
     * multi-line recipe string as a `<pre>` code block.
     */
    private function _setupRecipe()
    {
        return array(
            <<<'EOT'
cat >/etc/rsyslog.d/30-mail-world-readable.conf <<'EOF'
# Make only mail logs world-readable.
# This applies only to the mail log rule below.
$FileCreateMode 0644
mail.*    -/var/log/mail.log
# Reset to default afterwards so other logs are unaffected.
$FileCreateMode 0640
EOF
systemctl restart rsyslog
# rsyslog's FileCreateMode only applies when the file is CREATED.
# If /var/log/mail.log already existed, set its mode now (one-time;
# the next log rotation will re-create it with the FileCreateMode).
chmod 644 /var/log/mail.log
EOT
        );
    }

    /**
     * Two-largest-units humanisation, shape lifted from DD-40's
     * MispCacheStatusWidget which itself lifted from
     * IndexTable/Fields/caching.ctp.  Kept verbatim so the mail-log
     * "ago" reads identically to the cache-status "ago" — a single
     * humanisation shape across the operational widget family.
     */
    private function _humanizeAge($seconds)
    {
        $seconds = (int)$seconds;
        if ($seconds < 60) {
            return $seconds . 's';
        }
        $days = (int)floor($seconds / 86400);
        $remAfterDays = $seconds - $days * 86400;
        $hours = (int)floor($remAfterDays / 3600);
        $remAfterHours = $remAfterDays - $hours * 3600;
        $minutes = (int)floor($remAfterHours / 60);
        $secs = $remAfterHours - $minutes * 60;
        if ($days > 0) {
            return $hours > 0 ? sprintf('%dd %dh', $days, $hours) : sprintf('%dd', $days);
        }
        if ($hours > 0) {
            return $minutes > 0 ? sprintf('%dh %dm', $hours, $minutes) : sprintf('%dh', $hours);
        }
        return $secs > 0 ? sprintf('%dm %ds', $minutes, $secs) : sprintf('%dm', $minutes);
    }

    private function _humanizeBytes($bytes)
    {
        $bytes = (int)$bytes;
        if ($bytes >= 1048576) {
            return sprintf('%.1f MB', $bytes / 1048576);
        }
        if ($bytes >= 1024) {
            return sprintf('%d KB', (int)($bytes / 1024));
        }
        return $bytes . ' B';
    }

    private function _truncate($s, $max)
    {
        $s = (string)$s;
        if (mb_strlen($s) <= $max) {
            return $s;
        }
        return mb_substr($s, 0, $max - 1) . '…';
    }
}
