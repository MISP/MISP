<?php
/*
 * user_status.ctp — Active / Disabled pill for a user row.
 * Expected:
 *   $field['data_path'] => path to the "disabled" boolean (default 'User.disabled')
 */
$disabled = !empty(Hash::get($row, $field['data_path'] ?? 'User.disabled'));

echo sprintf(
    '<span class="badge rounded-pill %s d-inline-flex align-items-center gap-1"><i class="fas fa-%s"></i>%s</span>',
    $disabled ? 'text-bg-danger' : 'text-bg-success',
    $disabled ? 'ban' : 'circle-check',
    $disabled ? __('Disabled') : __('Active')
);
