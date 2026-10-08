<?php
$role = Hash::get($row, $field['data_path']);

if (empty($role['name'])) {
    return;
}

// Glyph and colour come from app/Lib/Tools/RoleGlyph.php
$glyph = $this->RoleGlyph->get($role);

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
    '<span class="d-inline-flex align-items-center justify-content-center rounded-2 flex-shrink-0" '
        . 'style="%s background-color:%s; color:%s; border:1px solid %s33;">'
        . '<i class="%s" style="%s"></i></span>'
        . '<span class="fw-semibold text-body">%s</span>',
    $boxStyle,
    h($glyph['tint']),
    h($glyph['colour']),
    h($glyph['colour']),
    h($glyph['icon']),
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
