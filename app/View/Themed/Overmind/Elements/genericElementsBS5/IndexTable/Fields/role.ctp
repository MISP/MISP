<?php
$role = Hash::get($row, $field['data_path']);

if (empty($role['name'])) {
    return;
}

if ($role['name'] === 'admin') {
    $color = 'danger';    $icon = 'fa-shield-halved';
} elseif ($role['name'] === 'Org Admin') {
    $color = 'primary';   $icon = 'fa-user-shield';
} elseif ($role['name'] === 'Publisher') {
    $color = 'success';   $icon = 'fa-upload';
} elseif ($role['name'] === 'Sync user') {
    $color = 'warning';   $icon = 'fa-arrows-rotate';
} elseif ($role['name'] === 'Read Only') {
    $color = 'galaxy';    $icon = 'fa-book-open-reader';
} elseif ($role['name'] === 'User') {
    $color = 'secondary'; $icon = 'fa-user';
} else {
    $color = 'dark';      $icon = 'fa-user-pen';
}

// Optional larger variant (e.g. when the chip is reused as a page header title).
$size = $field['size'] ?? 'sm';
if ($size === 'lg') {
    $boxStyle = 'width:2.5rem; height:2.5rem;';
    $iconStyle = 'font-size:1.3rem;';
} else {
    $boxStyle = 'width:1.5rem; height:1.5rem;';
    $iconStyle = 'font-size:.8rem;';
}

$chip = sprintf(
    '<span class="d-inline-flex align-items-center justify-content-center rounded-2 text-bg-%s text-white flex-shrink-0" '
        . 'style="%s"><i class="fas %s" style="%s"></i></span>'
        . '<span class="fw-semibold text-body">%s</span>',
    $color,
    $boxStyle,
    $icon,
    $iconStyle,
    h($role['name'])
);

if (!empty($field['no_link'])) {
    echo sprintf(
        '<span class="d-inline-flex align-items-center gap-2">%s</span>',
        $chip
    );
} else {
    echo sprintf(
        '<a href="%s/roles/view/%s" class="d-inline-flex align-items-center gap-2 text-decoration-none">%s</a>',
        h($baseurl),
        h($role['id'] ?? 0),
        $chip
    );
}
