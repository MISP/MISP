<?php
// A server's remote org and the local org owning the connection.
$orgs = [
    __('Remote') => $row['RemoteOrg'] ?? [],
    __('Owner') => $row['Organisation'] ?? [],
];
?>
<div class="d-flex flex-column gap-2">
    <?php foreach ($orgs as $label => $org): ?>
        <?php if (!empty($org['id']) && !empty($org['name'])): ?>
            <div class="d-flex flex-column">
                <span class="text-body-secondary small text-nowrap"><?= h($label) ?></span>
                <?= $this->element('genericElementsBS5/Badges/organisation', ['org' => $org]) ?>
            </div>
        <?php endif; ?>
    <?php endforeach; ?>
</div>
