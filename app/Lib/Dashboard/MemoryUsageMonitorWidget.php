<?php

App::uses('MonitorSeriesStore', 'Lib/Dashboard/Tools');

/**
 * Live memory-usage monitor widget (dashboard v2). Site-admin-only,
 * streaming alternative to MispSystemResourceWidget's static memory line:
 * it plots memory used-% as a rolling line.
 *
 * Reuses the MonitorLineChart render kind (DD-29): each handler() call
 * records the current sample into a Redis ring buffer and returns the
 * retained `window`s of history (DD-30); the renderer draws that series
 * and re-polls every `interval`s to extend it (autoRefreshDelay=false
 * keeps the board scheduler from re-rendering the tile). Not cached
 * (no $cache_duration) → every poll reads live.
 */
class MemoryUsageMonitorWidget
{
    public $title = 'Memory Usage Monitor';
    public $category = 'system';
    public $render = 'MonitorLineChart';
    public $width = 3;
    public $height = 3;
    public $description = 'Live memory usage (% used) as a rolling line graph. Site-admin only; samples every 10s, client-side history resets on reload.';
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
        $window = isset($options['window']) ? (int)$options['window'] : 180;
        $interval = isset($options['interval']) ? (int)$options['interval'] : 10;
        return array(
            'history' => MonitorSeriesStore::record('memory', $this->__usedPercent(), $window, $interval),
            'label'   => __('Memory'),
            'unit'    => '%',
            'yMax'    => 100,
        );
    }

    private function __usedPercent()
    {
        if (!is_readable('/proc/meminfo')) {
            return 0.0;
        }
        $meminfo = file_get_contents('/proc/meminfo');
        $total = $this->__kb($meminfo, 'MemTotal');
        if (empty($total) || $total <= 0) {
            return 0.0;
        }
        // MemAvailable is the kernel's estimate of memory available for new
        // workloads (it accounts for reclaimable page cache) — a truer
        // "free" than MemFree, which counts cache/buffers as used and so
        // overstates usage. Fall back to MemFree on pre-3.14 kernels that
        // don't export MemAvailable.
        $available = $this->__kb($meminfo, 'MemAvailable');
        if ($available === null) {
            $available = $this->__kb($meminfo, 'MemFree');
        }
        $available = max(0, (int)$available);
        return round((1 - $available / $total) * 100, 2);
    }

    private function __kb($meminfo, $key)
    {
        if (preg_match('/^' . preg_quote($key, '/') . ':\s+(\d+)\s+kB/mi', $meminfo, $m)) {
            return (int)$m[1];
        }
        return null;
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }
}
