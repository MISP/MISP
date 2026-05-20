<?php
$server = Hash::get($row, $field['data_path']);
if (empty($server)) {
    return;
}

$options = [
    __('Publish without email') => !empty($server['publish_without_email']),
    __('Self signed') => !empty($server['self_signed']),
    __('Skip proxy') => !empty($server['skip_proxy']),
    __('Unpublish event') => !empty($server['unpublish_event']),
];
?>
<div class="d-flex flex-column gap-1">
    <?php foreach ($options as $label => $enabled): ?>
        <span class="<?= $enabled ? 'text-success' : 'text-secondary' ?>">
            <i class="fa <?= $enabled ? 'fa-check' : 'fa-times' ?>"></i>
            <?= h($label) ?>
        </span>
    <?php endforeach; ?>
</div>
