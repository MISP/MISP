<?php
/*
 * What a remote listing tab (collections, objects) shows instead of its table
 * when the TAXII server could not be asked, or there is nothing to ask for.
 *
 *   $notice  array  ['kind' => 'danger'|'secondary', 'message' => string]
 */
$isError = ($notice['kind'] ?? 'danger') === 'danger';
?>
<div class="d-flex align-items-start gap-3 m-3 p-3 rounded-3 border
            <?= $isError ? 'border-danger-subtle bg-danger-subtle' : 'bg-body-tertiary' ?>">
    <i class="fas <?= $isError ? 'fa-plug-circle-xmark text-danger' : 'fa-circle-info text-secondary' ?> mt-1"></i>
    <div>
        <div class="fw-bold <?= $isError ? 'text-danger-emphasis' : '' ?>">
            <?= $isError
                ? __('The TAXII server could not be queried')
                : __('Nothing to list') ?>
        </div>
        <div class="small text-body-secondary"><?= h($notice['message'] ?? '') ?></div>
    </div>
</div>
