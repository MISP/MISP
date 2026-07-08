<?php
/*
 * role.ctp — role as a filled pill, coloured/iconed by the role's highest
 * permission tier. The role's real name is always shown (works for custom roles).
 * Expected:
 *   $field['data_path'] => path to the Role array (e.g. 'Role')
 */
$role = Hash::get($row, $field['data_path']);
if (empty($role['name'])) {
    return;
}

if (!empty($role['perm_site_admin'])) {
    $color = 'danger';  $icon = 'fa-shield-halved';
} elseif (!empty($role['perm_admin'])) {
    $color = 'warning'; $icon = 'fa-user-shield';
} elseif (!empty($role['perm_sync'])) {
    $color = 'info';    $icon = 'fa-arrows-rotate';
} else {
    $color = 'secondary'; $icon = 'fa-user';
}

echo sprintf(
    '<a href="%s/roles/view/%s" class="badge rounded-pill text-bg-%s text-decoration-none d-inline-flex align-items-center gap-1">'
        . '<i class="fas %s"></i>%s</a>',
    h($baseurl),
    h($role['id'] ?? 0),
    $color,
    $icon,
    h($role['name'])
);
