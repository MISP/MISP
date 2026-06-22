<?php

/**
 * Live disk-usage pie widget (dashboard v2). A site-admin-only, livelier
 * alternative to MispSystemResourceWidget's static disk line: it renders
 * used-vs-free as a donut and refreshes on the board scheduler every 10s
 * (a pie is a snapshot, so the standard re-render path is enough — unlike
 * the CPU/memory monitors which accumulate a client-side time series).
 *
 * Not cached: no $cache_duration, so renderWidget runs handler() live on
 * every poll (the WidgetCache::remember wrapper is a transparent
 * pass-through for widgets that don't opt in).
 */
class DiskUsageMonitorWidget
{
    public $title = 'Disk Usage Monitor';
    public $category = 'system';
    public $render = 'PieChart';
    public $width = 2;
    public $height = 3;
    public $description = 'Live disk usage (used vs free) of the MISP server filesystem as a pie chart. Site-admin only; refreshes every 10s.';
    public $cacheLifetime = false;
    public $autoRefreshDelay = 10;
    public $schema = array(
        'path' => array(
            'type' => 'string',
            'default' => '',
            'help' => 'Filesystem path to measure. Defaults to the MISP application directory.',
        ),
        'threshold' => array(
            'type' => 'int',
            'default' => 85,
            'help' => 'Used-percent threshold above which the Used slice turns red.',
        ),
    );
    public $placeholder =
'{
    "threshold": 85
}';

    public function handler(array $user, $options = array())
    {
        $path = !empty($options['path']) ? $options['path'] : APP;
        // disk_*_space return false for an unreadable path; guard so the
        // widget degrades to an explicit empty state rather than dividing
        // by a false/zero total.
        $total = @disk_total_space($path);
        $free  = @disk_free_space($path);
        if (empty($total) || $free === false) {
            return array(
                'slices'   => array(),
                'used_pct' => 0,
                'error'    => __('Disk path not measurable: %s', $path),
            );
        }
        $used = $total - $free;
        $threshold = isset($options['threshold']) ? (int)$options['threshold'] : 85;
        return array(
            'slices' => array(
                'Used' => $used,
                'Free' => $free,
            ),
            'used_pct'  => round($used / $total * 100, 2),
            'threshold' => $threshold,
            'path'      => $path,
        );
    }

    public function checkPermissions($user)
    {
        return !empty($user['Role']['perm_site_admin']);
    }
}
