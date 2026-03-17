<?php
$server = $row['Server'];

if (!empty($server['caching_enabled'])) {
    if (!empty($server['cache_timestamp'])) {
        $units = array('m', 'h', 'd');
        $intervals = array(60, 60, 24);
        $unit = 's';
        $last = time() - $server['cache_timestamp'];
        foreach ($units as $k => $v) {
            if ($last > $intervals[$k]) {
                $unit = $v;
                $last = floor($last / $intervals[$k]);
            } else {
                break;
            }
        }
        echo sprintf('<span class="blue bold">%s</span> %s', __('Age: %s%s', $last, $unit), '<span class="fa fa-check"></span>');
    } else {
        echo sprintf('<span class="red bold">%s</span> %s', __('Not cached'), '<span class="fa fa-check"></span>');
    }
}
else {
    echo '<span class="fa fa-times" role="img" aria-label="' . __('No') . '"></span>';
}
