<?php
$remoteOrg = $row['RemoteOrg'] ?? [];
$ownerOrg = $row['Organisation'] ?? [];
?>
<div class="d-flex flex-column gap-1">
    <?php if (!empty($remoteOrg['id']) && !empty($remoteOrg['name'])): ?>
        <a
            href="<?= h($baseurl . '/organisations/view/' . $remoteOrg['id']) ?>"
            class="text-decoration-none"
        >
            <strong><?= __('Remote') ?>:</strong> <?= h($remoteOrg['name']) ?>
        </a>
    <?php endif; ?>

    <?php if (!empty($ownerOrg['id']) && !empty($ownerOrg['name'])): ?>
        <a
            href="<?= h($baseurl . '/organisations/view/' . $ownerOrg['id']) ?>"
            class="text-decoration-none"
        >
            <strong><?= __('Owner') ?>:</strong> <?= h($ownerOrg['name']) ?>
        </a>
    <?php endif; ?>
</div>
