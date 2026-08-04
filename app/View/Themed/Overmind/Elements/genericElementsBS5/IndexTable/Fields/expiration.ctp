<?php
$exp = (int)(Hash::get($row, $field['data_path']) ?? 0);

if ($exp === 0) {
    echo '<span class="badge text-bg-success">' . __('Indefinite') . '</span>';
    return;
}

if ($exp <= time()) {
    printf(
        '<span class="badge text-bg-danger" title="%s">%s</span>',
        h(date('Y-m-d H:i:s', $exp)),
        __('Expired')
    );
    return;
}

$days = (int)floor(($exp - time()) / 86400);
$cls = $days <= 14 ? 'text-bg-warning' : 'text-bg-success';
printf(
    '<span class="badge %s" title="%s">%s</span>',
    $cls,
    h(__n('Expires in %s day', 'Expires in %s days', $days, $days)),
    h(date('Y-m-d', $exp))
);
