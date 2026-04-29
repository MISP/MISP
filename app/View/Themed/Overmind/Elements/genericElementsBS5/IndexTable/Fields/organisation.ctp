<?php
$org = Hash::extract($row, $field['data_path']);

if (empty($org)) {
    return;
}

$id = !empty($org['id']) ? $org['id'] : null;
$isCreator = $data_path === 'Orgc';
$isCard = isset($viewMode) && $viewMode === 'card';


?>

<div class="d-flex flex-column gap-1">

    <?php if ($isCard): ?>
        <div class="text-muted small">
            <?= $isCreator ? __('Creator Org') : __('Owner Org') ?>
        </div>
    <?php endif; ?>

    <div class="d-inline-flex align-items-center gap-2 text-nowrap">

        <?= $this->OrgImg->getOrgLogoV2($org, 24)?>

        <?php if (!empty($id)): ?>
            <a href="<?= $baseurl ?>/organisations/view/<?= h($id) ?>"
                class="text-decoration-none fw-semibold text-primary">
                <?= h($org['name']) ?>
            </a>
        <?php else: ?>
            <p class="text-decoration-none fw-semibold text-primary mb-0">
                <?= h($org[0]) ?>
            </p>
        <?php endif; ?>
    </div>

</div>