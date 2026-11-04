<?php
$org = Hash::extract($row, $field['data_path']);

if (empty($org)) {
    return;
}

if (!empty($org['id'])) {
    $id = $org['id'];
} elseif (!empty($org['uuid'])) {
    $id = $org['uuid'];
} else {
    $id = null;
}

$name = null;
if (empty($id)) {
    /*
     * Nothing to link to. Two shapes land here, and neither is a real
     * organisation: a contained association with no row behind it (a foreign
     * key of 0 — what MISP's bundled galaxies and clusters carry) comes back
     * all-null, and a model that has already swapped in
     * Organisation::GENERIC_MISP_ORGANISATION hands us an org whose id AND
     * uuid are both the string '0'. `default_org` is the field's chance to
     * name that case in its own words ('MISP', 'Default galaxy', ...); without
     * it we fall back to whatever name came with the row.
     */
    if (!empty($field['default_org'])) {
        $org = ['name' => $field['default_org']];
        $name = $field['default_org'];
    } elseif (!empty($org['name'])) {
        $name = $org['name'];
    } elseif (!empty($org[0])) {
        $name = $org[0];
    }

    // Nothing to name and nothing to link to: there is no cell to draw.
    if ($name === null) {
        return;
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
            <span class="fw-semibold text-body-secondary">
                <?= h($name) ?>
            </span>
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