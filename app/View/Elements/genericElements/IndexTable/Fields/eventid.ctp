<?php
echo sprintf(
    '<span class="text-nowrap"><a href="%s/events/view/%s" class="dblclickActionElement threat-level-%s" title="%s">%s</a> %s</span>',
    $baseurl,
    h($row['Event']['id']),
    strtolower(h($row['ThreatLevel']['name'])),
    h($row['Event']['info']),
    h($row['Event']['id']),
    !empty($row['Event']['protected']) ? sprintf('<i class="fas fa-lock" title="%s"></i>', __('Protected event')) : ''
);


