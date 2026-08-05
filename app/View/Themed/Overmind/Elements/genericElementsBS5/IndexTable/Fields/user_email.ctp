<?php
/*
 * user_email.ctp — user email linking to their (admin) view page.
 * Expected:
 *   $field['data_path'] => path to the email (default 'User.email')
 *   $field['id_path']   => path to the user id (default 'User.id')
 *   $field['url']       => link template with %id% (default admin view)
 */
$email = Hash::get($row, $field['data_path'] ?? 'User.email');
if (empty($email)) {
    return;
}
$uid = Hash::get($row, $field['id_path'] ?? 'User.id');
$template = $field['url'] ?? ($baseurl . '/admin/users/view/%id%');
$href = str_replace('%id%', rawurlencode((string)$uid), $template);

echo sprintf(
    '<a href="%s" class="fw-semibold text-decoration-none">%s</a>',
    h($href),
    h($email)
);
