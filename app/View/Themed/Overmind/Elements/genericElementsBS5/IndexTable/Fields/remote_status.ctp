<?php
/*
 * remote_status.ctp — whether a remote object (Cerebrate preview) is known
 * locally, and if so which fields differ.
 *
 * Expected:
 * $data_path => prefix of `exists_locally` / `differences` ('' for the row root)
 */

$prefix = $field['data_path'] ?? '';
$exists = !empty(Hash::get($row, $prefix . 'exists_locally'));
$differences = $exists ? (array)Hash::get($row, $prefix . 'differences') : [];

if (!$exists) {
    $colour = 'danger';
    $icon = 'fa-times-circle';
    $label = __('Not local');
    $text = __('Object does not exist locally.');
} elseif (empty($differences)) {
    $colour = 'success';
    $icon = 'fa-check-circle';
    $label = __('In sync');
    $text = __('Object exists locally.');
} else {
    $colour = 'warning';
    $icon = 'fa-rotate';
    $label = __('Differs');
    $text = __(
        'Object exists locally, but the following fields contain different information on the remote: %s',
        implode(', ', $differences)
    );
}
?>
<span class="badge rounded-pill bg-<?= $colour ?>-subtle text-<?= $colour ?>-emphasis
             border border-<?= $colour ?>-subtle"
      title="<?= h($text) ?>" data-bs-toggle="tooltip">
    <i class="fas <?= $icon ?> me-1"></i><?= h($label) ?>
</span>
