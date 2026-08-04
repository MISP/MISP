<?php
/*
 * user_link.ctp — renders a user email linking to that user's view page.
 * Expected:
 *   $field['data_path'] => path to the email (e.g. 'User.email')
 *   $field['id_path']   => path to the user id  (default 'User.id')
 */
$email = Hash::get($row, $field['data_path']);
if (empty($email)) {
    return;
}
$uid = Hash::get($row, $field['id_path'] ?? 'User.id');

echo sprintf(
    '<a href="%s/users/view/%s">%s</a>',
    h($baseurl),
    h($uid),
    h($email)
);
