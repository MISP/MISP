<?php
$server = Hash::get($row, $field['data_path']);
if (empty($server)) {
    return;
}
?>
<div class="d-flex flex-column gap-1">
    <span>
        <strong><?= __('Cert') ?>:</strong>
        <?= !empty($server['cert_file']) ? h($server['cert_file']) : __('None') ?>
    </span>
    <span>
        <strong><?= __('Client cert') ?>:</strong>
        <?= !empty($server['client_cert_file']) ?
            h($server['client_cert_file']) : __('None') ?>
    </span>
</div>
