<?php
$org = Hash::extract($row, $field['data_path']);

if (empty($org)) {
    return;
}

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

        <?php
        $logoUrl = $baseurl . '/organisations/getOrgLogo/' . h($org['id']);
        ?>

        <img src="<?= $logoUrl ?>"
                alt="<?= h($org['name']) ?>"
                height="24"
                class="rounded"
                onerror="this.style.display='none'">

        <a href="<?= $baseurl ?>/organisations/view/<?= h($org['id']) ?>"
            class="text-decoration-none fw-semibold text-primary">

            <?= h($org['name']) ?>

        </a>

    </div>

</div>