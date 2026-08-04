<?php
$org = Hash::extract($row, $field['data_path']);

// Opt-in fallback mirroring the legacy org element's 'default_org' (e.g.
// 'MISP' for default galaxy data owned by org 0): substituted when no real
// organisation is attached at the data_path.
if (empty($org['id']) && empty($org['uuid']) && empty($org['name']) && !empty($field['default_org'])) {
    $org = ['name' => $field['default_org']];
}

if (empty($org)) {
    return;
}

if (!empty($org['id'])){
    $id = $org['id'];
}
elseif (!empty($org['uuid'])){
    $id = $org['uuid'];
}
else {
    $id = null;
}

if (empty($id)) {
    if (!empty($org['name'])) {
        $name = $org['name'];
    } elseif (!empty($org[0])) {
        $name = $org[0];
    } else {
        $name = null;
    }
}
$isCreator = $data_path === 'Orgc';
$isCard = isset($viewMode) && $viewMode === 'card';

// Optionally surface the organisation description below the name
$showDescription = !empty($field['show_description']);
$description = $showDescription && !empty($org['description']) ? trim($org['description']) : '';
?>

<div class="d-flex flex-column gap-1">

    <?php if ($isCard && !isset($description)):  ?>
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
                <?= h($name) ?>
            </p>
        <?php endif; ?>
    </div>

    <?php if ($description !== ''): ?>
        <div class="text-muted small <?= $isCard ? '' : 'text-truncate' ?>"
             style="<?= $isCard ? '' : 'max-width: 22rem;' ?>"
             title="<?= h($description) ?>">
            <?= $isCard ? nl2br(h($description)) : h($description) ?>
        </div>
    <?php endif; ?>

</div>