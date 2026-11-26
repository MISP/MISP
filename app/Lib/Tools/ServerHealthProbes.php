<?php
App::uses('RedisTool', 'Tools');

/**
 * The health checks of the server settings page, one per independent probe.
 *
 * ServersController::serverDiagnostic() collects the data of one probe and
 * hands it to verdict(), which every surface reads: the probe's own card,
 * its tile on the Overview and the status dot in the navigation. The last
 * verdict of each probe is kept in Redis so the Overview and the navigation
 * can show it without re-running anything.
 *
 * Levels follow the pills of the page: 0 error, 1 warning, 2 OK, 3 n/a.
 */
class ServerHealthProbes
{
    const CACHE_PREFIX = 'misp:server_health:';
    const CACHE_TTL = 86400;

    /** Age past which the Overview re-runs a probe on its own. */
    const STALE_AFTER = 600;

    /**
     * @return array probe => title, icon, destination (the page showing its card)
     */
    public static function probes()
    {
        return array(
            'version' => array('title' => __('Version'), 'icon' => 'code-branch', 'destination' => 'version'),
            'php' => array('title' => __('PHP'), 'icon' => 'code', 'destination' => 'php'),
            'filesystem' => array('title' => __('File permissions'), 'icon' => 'folder-tree', 'destination' => 'php'),
            'dbSchema' => array('title' => __('Database schema'), 'icon' => 'database', 'destination' => 'database'),
            'dbSpace' => array('title' => __('Database space'), 'icon' => 'chart-column', 'destination' => 'database'),
            'dbConfig' => array('title' => __('Database configuration'), 'icon' => 'sliders', 'destination' => 'database'),
            'redis' => array('title' => __('Redis'), 'icon' => 'server', 'destination' => 'redis'),
            'workers' => array('title' => __('Workers'), 'icon' => 'gears', 'destination' => 'jobs'),
            'services' => array('title' => __('Services'), 'icon' => 'plug', 'destination' => 'services'),
            'modules' => array('title' => __('misp-modules'), 'icon' => 'puzzle-piece', 'destination' => 'services'),
            'stix' => array('title' => __('STIX libraries'), 'icon' => 'file-code', 'destination' => 'services'),
            'audit' => array('title' => __('Security audit'), 'icon' => 'shield-halved', 'destination' => 'audit'),
        );
    }

    /**
     * Probes shown as tiles on the Overview. Space usage is a report rather
     * than a verdict, so it only lives on the Database page.
     *
     * @return array
     */
    public static function overviewProbes()
    {
        return array_values(array_diff(array_keys(self::probes()), array('dbSpace')));
    }

    /**
     * @param string $probe
     * @return bool
     */
    public static function isKnown($probe)
    {
        return is_string($probe) && isset(self::probes()[$probe]);
    }

    /**
     * @param array $probes
     * @return array probe => ['level', 'label', 'summary', 'at'] for those with a stored verdict
     */
    public static function cached(array $probes)
    {
        $verdicts = array();
        try {
            $redis = RedisTool::init();
            foreach ($probes as $probe) {
                $raw = $redis->get(self::CACHE_PREFIX . $probe);
                if ($raw) {
                    $verdicts[$probe] = json_decode($raw, true);
                }
            }
        } catch (Exception $e) {
            // Without Redis every probe simply runs when its page is opened.
        }
        return $verdicts;
    }

    /**
     * @param string $probe
     * @param array $verdict
     * @return array The verdict, stamped with the time it was taken
     */
    public static function store($probe, array $verdict)
    {
        $verdict['at'] = time();
        try {
            RedisTool::init()->setex(self::CACHE_PREFIX . $probe, self::CACHE_TTL, json_encode($verdict));
        } catch (Exception $e) {
            // Caching is a convenience; the verdict is still returned.
        }
        return $verdict;
    }

    /**
     * @param array $verdicts
     * @return int|null The most severe level among them (3 = n/a counts as fine)
     */
    public static function worst(array $verdicts)
    {
        $worst = null;
        foreach ($verdicts as $verdict) {
            $level = (int)$verdict['level'] === 3 ? 2 : (int)$verdict['level'];
            $worst = $worst === null ? $level : min($worst, $level);
        }
        return $worst;
    }

    /**
     * @param string $probe
     * @param array $data The variables ServersController collected for it
     * @return array level, label (the card's badge), summary (the tile's second line)
     */
    public static function verdict($probe, array $data)
    {
        $method = 'verdict' . ucfirst($probe);
        return self::$method($data);
    }

    private static function make($level, $label, $summary = '')
    {
        return array('level' => $level, 'label' => $label, 'summary' => $summary);
    }

    private static function verdictVersion(array $data)
    {
        $states = array(
            'same' => array(2, __('Up to date')),
            'newer' => array(1, __('Development version')),
            'older' => array(1, __('Outdated')),
            'disabled' => array(3, __('Check disabled')),
            'error' => array(0, __('Check failed')),
        );
        $upToDate = isset($data['version']['upToDate']) ? $data['version']['upToDate'] : 'error';
        $state = isset($states[$upToDate]) ? $states[$upToDate] : $states['error'];
        $summary = isset($data['version']['current']) ? 'v' . ltrim($data['version']['current'], 'v') : __('Unknown version');
        if (!empty($data['branch'])) {
            $summary .= ' · ' . __('branch %s', $data['branch']);
        }
        return self::make($state[0], $state[1], $summary);
    }

    /**
     * @param string|false $version
     * @param array $data phpmin, phprec, phptoonew
     * @return array [level, label]
     */
    public static function phpVersionState($version, array $data)
    {
        if (!$version) {
            return array(0, __('Unknown'));
        }
        if (version_compare($version, $data['phptoonew']) >= 0) {
            return array(0, __('Unsupported'));
        }
        if (version_compare($version, $data['phpmin']) < 0) {
            return array(0, __('Unsupported, update ASAP'));
        }
        if (version_compare($version, $data['phprec']) < 0) {
            return array(1, __('Update recommended'));
        }
        return array(2, __('Up to date'));
    }

    /**
     * @param array $data
     * @return array Required PHP extensions and composer dependencies that are absent or outdated
     */
    public static function phpMissing(array $data)
    {
        $missing = array('extensions' => 0, 'dependencies' => 0);
        foreach ($data['extensions']['extensions'] as $info) {
            if ($info['required'] && (!$info['web_version'] || $info['web_version_outdated'])) {
                $missing['extensions']++;
            }
        }
        foreach ($data['extensions']['dependencies'] as $info) {
            if ($info['required'] && (!$info['version'] || $info['version_outdated'])) {
                $missing['dependencies']++;
            }
        }
        return $missing;
    }

    /**
     * @param array $data
     * @return int PHP limits below their recommended value
     */
    public static function phpLow(array $data)
    {
        $low = 0;
        foreach ($data['phpSettings'] as $setting) {
            if ($setting['value'] < $setting['recommended']) {
                $low++;
            }
        }
        return $low;
    }

    private static function verdictPhp(array $data)
    {
        $web = self::phpVersionState($data['phpversion'], $data);
        $cliVersion = isset($data['extensions']['cli']['phpversion']) ? $data['extensions']['cli']['phpversion'] : false;
        $cli = self::phpVersionState($cliVersion, $data);
        $missing = self::phpMissing($data);
        $low = self::phpLow($data);
        $summary = 'PHP ' . $data['phpversion'];

        if ($missing['extensions'] + $missing['dependencies'] > 0) {
            return self::make(0, __('%s required component(s) missing', $missing['extensions'] + $missing['dependencies']), $summary);
        }
        if ($web[0] < 2 || $cli[0] < 2) {
            $state = $web[0] <= $cli[0] ? $web : $cli;
            return self::make($state[0], $state[1], $summary);
        }
        if ($low) {
            return self::make(1, __('%s limit(s) below recommended', $low), $summary);
        }
        return self::make(2, __('OK'), $summary);
    }

    private static function verdictFilesystem(array $data)
    {
        $checked = 0;
        $issues = 0;
        foreach (array($data['writeableDirs'], $data['writeableFiles'], $data['readableFiles']) as $set) {
            foreach ($set as $error) {
                $checked++;
                if ($error > 0) {
                    $issues++;
                }
            }
        }
        $summary = __('%s paths checked', $checked);
        return $issues
            ? self::make(0, __('%s issue(s)', $issues), $summary)
            : self::make(2, __('All accessible'), $summary);
    }

    /**
     * @param array $diagnostics Server::dbSchemaDiagnostic()
     * @return int Column and index differences with the expected schema
     */
    public static function schemaDifferences(array $diagnostics)
    {
        $total = 0;
        foreach (array('diagnostic', 'diagnostic_index') as $key) {
            foreach ((isset($diagnostics[$key]) ? $diagnostics[$key] : array()) as $diffs) {
                $total += count($diffs);
            }
        }
        return $total;
    }

    private static function verdictDbSchema(array $data)
    {
        $schema = $data['dbSchemaDiagnostics'];
        $failed = (int)(isset($schema['migrations_failed']) ? $schema['migrations_failed'] : 0);
        $pending = (int)(isset($schema['migrations_pending']) ? $schema['migrations_pending'] : 0);
        $diffs = self::schemaDifferences($schema);
        $summary = __('db_version %s', isset($schema['actual_db_version']) ? $schema['actual_db_version'] : '?');

        if (!$data['dbEncodingStatus']) {
            return self::make(0, __('Incorrect encoding'), $summary);
        }
        if (!empty($schema['error'])) {
            return self::make(0, __('Check failed'), $summary);
        }
        if ($failed > 0) {
            return self::make(0, __('%s migration(s) failed', $failed), $summary);
        }
        if ($pending > 0) {
            return self::make(1, __('%s migration(s) pending', $pending), $summary);
        }
        if ($diffs > 0) {
            return self::make(1, __('%s schema difference(s)', $diffs), $summary);
        }
        return self::make(2, __('Schema matches'), $summary);
    }

    /**
     * @param float $bytes
     * @return string
     */
    public static function formatBytes($bytes)
    {
        $bytes = (float)$bytes;
        $units = array('B', 'KB', 'MB', 'GB', 'TB');
        $i = 0;
        while ($bytes >= 1024 && $i < count($units) - 1) {
            $bytes /= 1024;
            $i++;
        }
        return number_format($bytes, $i === 0 ? 0 : 1, ',', ' ') . ' ' . $units[$i];
    }

    private static function verdictDbSpace(array $data)
    {
        $total = 0;
        $reclaimable = 0;
        foreach ($data['dbDiagnostics'] as $table) {
            $total += (int)(isset($table['data_in_bytes']) ? $table['data_in_bytes'] : 0)
                + (int)(isset($table['index_in_bytes']) ? $table['index_in_bytes'] : 0);
            $reclaimable += (int)(isset($table['reclaimable_in_bytes']) ? $table['reclaimable_in_bytes'] : 0);
        }
        return self::make(2, self::formatBytes($total), __('%s reclaimable', self::formatBytes($reclaimable)));
    }

    private static function verdictDbConfig(array $data)
    {
        if (empty($data['dbConfiguration'])) {
            return self::make(3, __('Not available'), __('Only reported for MySQL and MariaDB'));
        }
        $off = 0;
        foreach ($data['dbConfiguration'] as $setting) {
            if ($setting['value'] != $setting['recommended']) {
                $off++;
            }
        }
        $summary = __('%s variables checked', count($data['dbConfiguration']));
        return $off
            ? self::make(1, __('%s off recommendation', $off), $summary)
            : self::make(2, __('OK'), $summary);
    }

    private static function verdictRedis(array $data)
    {
        $info = $data['redisInfo'];
        if (empty($info['extensionVersion'])) {
            return self::make(0, __('Extension missing'));
        }
        if (empty($info['connection'])) {
            return self::make(0, __('Unreachable'));
        }
        $version = isset($info['redis_version']) ? $info['redis_version'] : '';
        $summary = $version !== '' ? __('Server %s', $version) : '';
        if (isset($info['used_memory'])) {
            $summary .= ($summary !== '' ? ' · ' : '') . __('%s used', self::formatBytes($info['used_memory']));
        }
        return self::make(2, __('Connected'), $summary);
    }

    /**
     * @param array $workers Server::workerDiagnostics()
     * @return array [queues, queues with no live worker]
     */
    public static function queueState(array $workers)
    {
        $queues = 0;
        $down = 0;
        foreach (array('default', 'prio', 'email', 'cache', 'update', 'scheduler') as $queue) {
            if (!isset($workers[$queue])) {
                continue;
            }
            $queues++;
            if (empty($workers[$queue]['ok'])) {
                $down++;
            }
        }
        return array($queues, $down);
    }

    private static function verdictWorkers(array $data)
    {
        if (empty($data['worker_array'])) {
            return self::make(3, __('Background jobs disabled'));
        }
        if (Configure::read('SimpleBackgroundJobs.enabled') && empty($data['worker_array']['supervisord_status'])) {
            return self::make(0, __('Supervisor unreachable'));
        }
        list($queues, $down) = self::queueState($data['worker_array']);
        $summary = __('%s of %s queues running', $queues - $down, $queues);
        if ($down) {
            return self::make($down === $queues ? 0 : 1, __('%s queue(s) without worker', $down), $summary);
        }
        return self::make(2, __('All queues running'), $summary);
    }

    /**
     * Level of each external service, shared by the card rows and the verdict.
     *
     * @param array $data
     * @return array service => level
     */
    public static function serviceLevels(array $data)
    {
        $sessionLevels = array(0 => 2, 1 => 0, 2 => 1, 8 => 3, 9 => 0);
        return array(
            'gpg' => $data['gpgStatus']['status'] === 0 ? 2 : 0,
            'proxy' => $data['proxyStatus'] === 0 ? 2 : ($data['proxyStatus'] === 1 ? 3 : 0),
            'session' => isset($sessionLevels[$data['sessionStatus']['error_code']]) ? $sessionLevels[$data['sessionStatus']['error_code']] : 0,
            'zmq' => $data['zmqStatus'] === 0 ? 2 : ($data['zmqStatus'] === 1 ? 3 : 0),
            'yara' => (empty($data['yaraStatus']['test_run']) || empty($data['yaraStatus']['operational'])) ? 0 : 2,
            'scan' => !empty($data['attachmentScan']['status']) ? 2 : 3,
        );
    }

    private static function verdictServices(array $data)
    {
        $levels = self::serviceLevels($data);
        $errors = count(array_keys($levels, 0, true));
        $warnings = count(array_keys($levels, 1, true));
        $summary = __('GnuPG, proxy, sessions, ZeroMQ, YARA, attachment scan');
        if ($errors) {
            return self::make(0, __('%s issue(s)', $errors), $summary);
        }
        if ($warnings) {
            return self::make(1, __('%s warning(s)', $warnings), $summary);
        }
        return self::make(2, __('OK'), $summary);
    }

    private static function verdictModules(array $data)
    {
        $enabled = 0;
        $broken = 0;
        foreach ($data['moduleTypes'] as $type) {
            $status = $data['moduleStatus'][$type];
            if ($status !== 1) {
                $enabled++;
            }
            if ($status > 1) {
                $broken++;
            }
        }
        $summary = __('%s of %s module systems enabled', $enabled, count($data['moduleTypes']));
        return $broken
            ? self::make(0, __('%s unreachable', $broken), $summary)
            : self::make(2, __('OK'), $summary);
    }

    private static function verdictStix(array $data)
    {
        $stix = $data['stix'];
        if ($stix['operational'] === -1) {
            return self::make(0, __('Test script failed'));
        }
        if (empty($stix['test_run'])) {
            return self::make(0, __('Diagnostics failed'));
        }
        if ($stix['operational'] === 0) {
            return self::make(0, __('Libraries missing'));
        }
        if (!empty($stix['invalid_version'])) {
            return self::make(1, __('Versions to update'));
        }
        return self::make(2, __('OK'), __('misp-stix and its dependencies'));
    }

    /**
     * @param array $audit SecurityAudit::run()
     * @return array Flat list of findings: area, level (0 error, 1 warning, 3 hint), message, link
     */
    public static function auditFindings(array $audit)
    {
        $levels = array('error' => 0, 'warning' => 1, 'hint' => 3);
        $findings = array();
        foreach ($audit as $area => $errors) {
            foreach ($errors as $error) {
                $findings[] = array(
                    'area' => $area,
                    'level' => isset($levels[$error[0]]) ? $levels[$error[0]] : 3,
                    'message' => $error[1],
                    'link' => isset($error[2]) ? $error[2] : null,
                );
            }
        }
        return $findings;
    }

    private static function verdictAudit(array $data)
    {
        $findings = self::auditFindings($data['securityAudit']);
        if (empty($findings)) {
            return self::make(2, __('All checks passed'));
        }
        $levels = array_column($findings, 'level');
        $errors = count(array_keys($levels, 0, true));
        $warnings = count(array_keys($levels, 1, true));
        $summary = __('%s error(s), %s warning(s)', $errors, $warnings);
        if ($errors) {
            return self::make(0, __('%s finding(s)', count($findings)), $summary);
        }
        if ($warnings) {
            return self::make(1, __('%s finding(s)', count($findings)), $summary);
        }
        return self::make(2, __('%s hint(s)', count($findings)), $summary);
    }
}
