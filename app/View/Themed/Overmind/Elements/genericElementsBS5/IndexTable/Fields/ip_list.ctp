<?php
/*
 * ip_list.ctp — renders a list of IPs as monospace badges.
 */
$ips = Hash::get($row, $field['data_path']);

if (empty($ips)) {
    echo '<span class="text-muted">' . h($field['empty'] ?? '—') . '</span>';
    return;
}

if (!is_array($ips)) {
    $ips = preg_split('/[\r\n,]+/', trim((string)$ips), -1, PREG_SPLIT_NO_EMPTY);
}

echo implode(' ', array_map(function ($ip) {
    return '<span class="badge text-bg-light border font-monospace">' . h($ip) . '</span>';
}, $ips));
