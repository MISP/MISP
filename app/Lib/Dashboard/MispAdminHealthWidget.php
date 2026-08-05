<?php

/**
 * MISP Health — application-layer health rollup widget (DD-39).
 *
 * Issue-only display: only checks that are *not* green emit rows. A
 * healthy MISP shows just the "All checks passing" header — that
 * absence-of-rows is the widget's good-news signal.
 *
 * Pure consumer of existing `Server::*Diagnostics()` methods — no
 * diagnostic logic is re-implemented here. The 8 user-specified checks:
 *
 *   1. MISP version vs latest tagged release (`getCurrentGitStatus`)
 *   2. PHP setting under-provisioned (`getIniSetting` × recommended)
 *   3. MySQL setting under-provisioned (`dbConfiguration`)
 *   4. Filesystem read/write permission issues (`writeable*Diagnostics`,
 *      `readableFilesDiagnostics` — rolled up into one row)
 *   5. Module system not reachable (`moduleDiagnostics` per type)
 *   6. GnuPG not configured correctly (`gpgDiagnostics` — status 2-4)
 *   7. STIX library status failure (`stixDiagnostics`)
 *   8. Session handler not `php_redis` (`sessionDiagnostics`)
 *   9. DB updates pending / locked / failing (`dbSchemaDiagnostic`)
 *
 * Site-admin only. Render kind HealthList (DD-39).
 *
 * Caching (DD-20): 5min via `$cache_duration` — `stixDiagnostics()`
 * spawns a Python subprocess, `moduleDiagnostics()` HTTP-pings the
 * module endpoints (×3 module types), `dbConfiguration()` runs
 * `SHOW VARIABLES` — real work; caching at 5min keeps the widget
 * cheap to render without hiding a fresh incident for long.
 */
class MispAdminHealthWidget
{
    public $title = 'MISP Health';
    public $category = 'system';
    public $render = 'HealthList';
    public $width = 3;
    public $height = 4;
    public $params = array();
    public $schema = array();
    public $description = 'Application-layer health rollup: surfaces only checks that are not green.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 60;
    // DD-20: 5min generic widget cache. Empty config → single shared
    // cache entry across site-admins. Diagnostic calls do real work
    // (Python subprocess, HTTP module pings, SHOW VARIABLES).
    public $cache_duration = 300;

    /** @var Server */
    private $Server;

    public function handler($user, $options = array())
    {
        $this->Server = ClassRegistry::init('Server');
        $rows = array();

        $this->_addVersionRow($rows);
        $this->_addPhpRows($rows);
        $this->_addMysqlRows($rows);
        $this->_addPermsRow($rows);
        $this->_addModuleRows($rows);
        $this->_addGpgRow($rows);
        $this->_addStixRows($rows);
        $this->_addSessionRow($rows);
        $this->_addDbUpdateRows($rows);

        $issues = count($rows);
        $worst = 'success';
        foreach ($rows as $r) {
            if (($r['severity_class'] ?? '') === 'danger') {
                $worst = 'danger';
                break;
            }
            if (($r['severity_class'] ?? '') === 'warning') {
                $worst = 'warning';
            }
        }

        if ($issues === 0) {
            $headerValue = __('All checks passing');
            $headerSev = 'success';
        } elseif ($issues === 1) {
            $headerValue = __('1 issue found');
            $headerSev = $worst;
        } else {
            $headerValue = sprintf(__('%d issues found'), $issues);
            $headerSev = $worst;
        }

        $header = array(
            'type' => 'header',
            'severity' => $headerSev,
            'value' => $headerValue,
        );
        array_unshift($rows, $header);
        return $rows;
    }

    public function checkPermissions($user)
    {
        if (empty($user['Role']['perm_site_admin'])) {
            return false;
        }
        return true;
    }

    // --- per-check emitters -----------------------------------------

    private function _addVersionRow(array &$rows)
    {
        try {
            $gitStatus = $this->Server->getCurrentGitStatus(true);
        } catch (Exception $e) {
            return;
        }
        if (empty($gitStatus['version']) || !isset($gitStatus['version']['upToDate'])) {
            return;
        }
        // Only 'older' surfaces — 'error' / 'disabled' mean "couldn't
        // check", not "outdated"; surfacing those would be noise on an
        // air-gapped install.
        if ($gitStatus['version']['upToDate'] !== 'older') {
            return;
        }
        $rows[] = array(
            'type' => 'check',
            'check' => 'misp-version-outdated',
            'name' => __('MISP version outdated'),
            'detail' => sprintf(
                __('current %s, newest %s'),
                (string)($gitStatus['version']['current'] ?? '?'),
                (string)($gitStatus['version']['newest'] ?? '?')
            ),
            'severity_class' => 'warning',
            'drilldown' => '/servers/serverSettings/diagnostics',
        );
    }

    private function _addPhpRows(array &$rows)
    {
        // Mirrors the recommended table in ServersController::serverSettings.
        $settings = array(
            'memory_limit'        => array('recommended' => 2048, 'unit' => 'MB'),
            'max_execution_time'  => array('recommended' => 300,  'unit' => 'seconds'),
            'upload_max_filesize' => array('recommended' => 50,   'unit' => 'MB'),
            'post_max_size'       => array('recommended' => 50,   'unit' => 'MB'),
        );
        foreach ($settings as $name => $meta) {
            $raw = $this->Server->getIniSetting($name);
            if ($raw === false || $raw === null || $raw === '') {
                continue;
            }
            $value = $raw;
            if ($meta['unit'] === 'MB' && is_numeric($raw)) {
                $value = (int)floor((int)$raw / 1024 / 1024);
            }
            if ((int)$value < (int)$meta['recommended']) {
                $rows[] = array(
                    'type' => 'check',
                    'check' => 'php-' . $name,
                    'name' => sprintf(__('PHP %s below recommended'), $name),
                    'detail' => sprintf(
                        '%s %s (recommended %s %s)',
                        $value,
                        $meta['unit'],
                        $meta['recommended'],
                        $meta['unit']
                    ),
                    'severity_class' => 'warning',
                    'drilldown' => '/servers/serverSettings/diagnostics',
                );
            }
        }
    }

    private function _addMysqlRows(array &$rows)
    {
        try {
            $config = $this->Server->dbConfiguration();
        } catch (Exception $e) {
            return;
        }
        if (!is_array($config) || empty($config)) {
            return;
        }
        foreach ($config as $entry) {
            if (!isset($entry['name'], $entry['value'], $entry['recommended'])) {
                continue;
            }
            $under = false;
            if (is_numeric($entry['recommended']) && is_numeric($entry['value'])) {
                $under = ((float)$entry['value'] < (float)$entry['recommended']);
            } else {
                $under = ((string)$entry['value'] !== (string)$entry['recommended']);
            }
            if (!$under) {
                continue;
            }
            $rows[] = array(
                'type' => 'check',
                'check' => 'mysql-' . $entry['name'],
                'name' => sprintf(__('MySQL %s below recommended'), $entry['name']),
                'detail' => sprintf(
                    '%s (recommended %s)',
                    (string)$entry['value'],
                    (string)$entry['recommended']
                ),
                'severity_class' => 'warning',
                'drilldown' => '/servers/serverSettings/diagnostics',
            );
        }
    }

    private function _addPermsRow(array &$rows)
    {
        $errs = 0;
        $dirs   = $this->Server->writeableDirsDiagnostics($errs);
        $errs = 0;
        $wfiles = $this->Server->writeableFilesDiagnostics($errs);
        $errs = 0;
        $rfiles = $this->Server->readableFilesDiagnostics($errs);

        $notWritable = 0;  // value === 2
        $notFound    = 0;  // value === 1
        $merged = array_merge(is_array($dirs) ? $dirs : array(),
                              is_array($wfiles) ? $wfiles : array());
        foreach ($merged as $path => $v) {
            $iv = (int)$v;
            if ($iv === 2) {
                $notWritable++;
            } elseif ($iv === 1) {
                $notFound++;
            }
        }
        // For readable-only files, "1" means not readable, which is
        // a hard failure (the STIX test script can't even be invoked).
        if (is_array($rfiles)) {
            foreach ($rfiles as $path => $v) {
                if ((int)$v === 1) {
                    $notWritable++;
                }
            }
        }

        if ($notWritable === 0 && $notFound === 0) {
            return;
        }
        $sev = $notWritable > 0 ? 'danger' : 'warning';
        $detail = sprintf(
            __('%d not writable, %d not found'),
            $notWritable,
            $notFound
        );
        $rows[] = array(
            'type' => 'check',
            'check' => 'filesystem-perms',
            'name' => __('Filesystem read/write issues'),
            'detail' => $detail,
            'severity_class' => $sev,
            'drilldown' => '/servers/serverSettings/diagnostics',
        );
    }

    private function _addModuleRows(array &$rows)
    {
        // Cortex is intentionally excluded — it's a different infra
        // surface (third-party engine) and most instances run without
        // it; surfacing it as "not reachable" would be noise.
        $types = array('Enrichment', 'Import', 'Export');
        foreach ($types as $type) {
            $errs = 0;
            try {
                $status = $this->Server->moduleDiagnostics($errs, $type);
            } catch (Exception $e) {
                continue;
            }
            // 0 = OK; 1 = disabled (user-intentional, skip); 2 =
            // enabled but no modules returned; any other value = error
            // message from the module HTTP call.
            if ($status === 0 || $status === 1) {
                continue;
            }
            if ($status === 2) {
                $rows[] = array(
                    'type' => 'check',
                    'check' => 'module-' . strtolower($type),
                    'name' => sprintf(__('%s module system not reachable'), $type),
                    'detail' => __('Enabled but returned no modules'),
                    'severity_class' => 'warning',
                    'drilldown' => '/servers/serverSettings/diagnostics',
                );
                continue;
            }
            $detail = is_string($status) ? mb_substr($status, 0, 120) : '';
            $rows[] = array(
                'type' => 'check',
                'check' => 'module-' . strtolower($type),
                'name' => sprintf(__('%s module system not reachable'), $type),
                'detail' => $detail,
                'severity_class' => 'danger',
                'drilldown' => '/servers/serverSettings/diagnostics',
            );
        }
    }

    private function _addGpgRow(array &$rows)
    {
        $errs = 0;
        $gpg = $this->Server->gpgDiagnostics($errs);
        $status = (int)($gpg['status'] ?? 0);
        // 0 = OK; 1 = not configured (could be intentional on a
        // consumer-only instance — skip); 2-4 = configured but broken.
        if ($status === 0 || $status === 1) {
            return;
        }
        $explain = array(
            2 => __('GnuPG library load failed'),
            3 => __('Signing key / passphrase issue'),
            4 => __('Signing test failed'),
        );
        $rows[] = array(
            'type' => 'check',
            'check' => 'gnupg-config',
            'name' => __('GnuPG not configured correctly'),
            'detail' => isset($explain[$status]) ? $explain[$status] : __('Unknown error'),
            'severity_class' => 'danger',
            'drilldown' => '/servers/serverSettings/diagnostics',
        );
    }

    private function _addStixRows(array &$rows)
    {
        $errs = 0;
        try {
            $stix = $this->Server->stixDiagnostics($errs);
        } catch (Exception $e) {
            return;
        }
        if (!is_array($stix)) {
            return;
        }
        $operational = isset($stix['operational']) ? (int)$stix['operational'] : 1;
        if ($operational !== 1) {
            $rows[] = array(
                'type' => 'check',
                'check' => 'stix-operational',
                'name' => __('STIX library status failure'),
                'detail' => empty($stix['test_run'])
                    ? __('Test script did not run')
                    : __('Test script reported failure'),
                'severity_class' => 'danger',
                'drilldown' => '/servers/serverSettings/diagnostics',
            );
            return;
        }
        if (!empty($stix['invalid_version'])) {
            $rows[] = array(
                'type' => 'check',
                'check' => 'stix-versions',
                'name' => __('STIX library versions outdated'),
                'detail' => __('One or more STIX-stack libraries below the expected version'),
                'severity_class' => 'warning',
                'drilldown' => '/servers/serverSettings/diagnostics',
            );
        }
    }

    private function _addSessionRow(array &$rows)
    {
        $errs = 0;
        $session = $this->Server->sessionDiagnostics($errs);
        $handler = (string)($session['handler'] ?? 'unknown');
        if ($handler === 'php_redis') {
            return;
        }
        $rows[] = array(
            'type' => 'check',
            'check' => 'session-handler',
            'name' => __('Session handler not set to php_redis'),
            'detail' => sprintf(__('Current handler: %s'), $handler),
            'severity_class' => 'warning',
            'drilldown' => '/servers/serverSettings/diagnostics',
        );
    }

    private function _addDbUpdateRows(array &$rows)
    {
        try {
            $diag = $this->Server->dbSchemaDiagnostic();
        } catch (Exception $e) {
            return;
        }
        if (!is_array($diag)) {
            return;
        }
        if (!empty($diag['update_fail_number_reached'])) {
            $rows[] = array(
                'type' => 'check',
                'check' => 'db-update-failed',
                'name' => __('Database updates are failing'),
                'detail' => __('Update failure threshold reached — manual intervention required'),
                'severity_class' => 'danger',
                'drilldown' => '/servers/serverSettings/diagnostics',
            );
        }
        if (!empty($diag['update_locked'])) {
            $rows[] = array(
                'type' => 'check',
                'check' => 'db-update-locked',
                'name' => __('Database updates are locked'),
                'detail' => sprintf(
                    __('Remaining lock time: %s s'),
                    (string)($diag['remaining_lock_time'] ?? '?')
                ),
                'severity_class' => 'warning',
                'drilldown' => '/servers/serverSettings/diagnostics',
            );
        }
        $actual   = isset($diag['actual_db_version']) ? (string)$diag['actual_db_version'] : '';
        $expected = isset($diag['expected_db_version']) ? (string)$diag['expected_db_version'] : '';
        if ($actual !== '' && $expected !== '' && $expected !== '?' && $actual !== $expected) {
            $rows[] = array(
                'type' => 'check',
                'check' => 'db-version-mismatch',
                'name' => __('Database schema not up-to-date'),
                'detail' => sprintf(
                    __('db_version %s, expected %s'),
                    $actual,
                    $expected
                ),
                'severity_class' => 'warning',
                'drilldown' => '/servers/serverSettings/diagnostics',
            );
        }
    }
}
