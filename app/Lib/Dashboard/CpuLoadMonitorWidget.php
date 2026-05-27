<?php

/**
 * Live CPU-load monitor widget (dashboard v2). A site-admin-only,
 * streaming alternative to MispSystemResourceWidget's static load line:
 * it plots the 1-minute load average normalized to % of cores
 * (sys_getloadavg()[0] / cores * 100) — a 0–100%+ "saturation" reading
 * that can exceed 100 on an overloaded host.
 *
 * Each handler() call returns ONE current sample. The MonitorLineChart
 * renderer accumulates a rolling time series client-side by polling this
 * handler every `interval` seconds (autoRefreshDelay=false keeps the board
 * scheduler from re-rendering the tile). Not cached (no $cache_duration),
 * so every poll reads live.
 */
class CpuLoadMonitorWidget
{
    public $title = 'CPU Load Monitor';
    public $category = 'system';
    public $render = 'MonitorLineChart';
    public $width = 3;
    public $height = 3;
    public $description = 'Live CPU load (1-minute load average as % of cores) as a rolling line graph. Site-admin only; samples every 10s, client-side history resets on reload.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = false;
    public $schema = array(
        'window' => array(
            'type' => 'int',
            'default' => 180,
            'help' => 'Rolling time window shown, in seconds (client-side; resets on reload).',
        ),
        'interval' => array(
            'type' => 'int',
            'default' => 10,
            'help' => 'Sampling interval in seconds.',
        ),
    );
    public $placeholder =
'{
    "window": 180,
    "interval": 10
}';

    public function handler(array $user, $options = array())
    {
        $cores = $this->__cpuCount();
        $load = function_exists('sys_getloadavg') ? sys_getloadavg() : false;
        $oneMin = (is_array($load) && isset($load[0])) ? (float)$load[0] : 0.0;
        return array(
            'value' => round($oneMin / $cores * 100, 2),
            'label' => __('CPU'),
            'unit'  => '%',
            'yMax'  => 100,
        );
    }

    /**
     * Logical core count from /proc/cpuinfo (one "processor : N" line per
     * core). Falls back to 1 so the normalization never divides by zero on
     * a platform without /proc.
     */
    private function __cpuCount()
    {
        if (is_readable('/proc/cpuinfo')) {
            $n = preg_match_all('/^processor\s*:/mi', file_get_contents('/proc/cpuinfo'));
            if ($n) {
                return $n;
            }
        }
        return 1;
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }
}
