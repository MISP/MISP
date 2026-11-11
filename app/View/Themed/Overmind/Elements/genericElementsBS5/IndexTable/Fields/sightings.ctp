<?php
/*
 * Sighting counts (sighting / false positive / expiration) of one attribute,
 * with a per-organisation popover and, for a role with perm_sighting, the
 * add buttons. The clicks are handled by installSightingActions() in
 * mispOvermind.js.
 *
 * The statistics come in two shapes: the global index passes
 * $field['sightings']['data'] keyed by attribute id, while the event view and
 * the object index carry them on the row itself, under 'Sighting'. Both are
 * keyed by 'sighting', 'false-positive' and 'expiration'.
 */
$isCard = isset($viewMode) && $viewMode === 'card';
$attribute = isset($row['Attribute']) ? $row['Attribute'] : $row;
if (empty($attribute['id'])) {
    return;
}

$objectId = (int)$attribute['id'];
$types = ['sighting', 'false-positive', 'expiration'];
$stats = $field['sightings']['data'][$objectId] ?? ($attribute['Sighting'] ?? []);
$stats = array_intersect_key(is_array($stats) ? $stats : [], array_flip($types));
$count = function ($type) use ($stats) {
    return (int)($stats[$type]['count'] ?? 0);
};

$myOrgName = $me['Organisation']['name'] ?? '';
$titles = [
    'sighting' => __('Sightings'),
    'false-positive' => __('False positives'),
    'expiration' => __('Expiration'),
];
$popLines = [];
foreach ($types as $type) {
    if (empty($stats[$type]['orgs'])) {
        continue;
    }
    $popLines[] = '<div class="fw-semibold small mt-1 mb-1">' . h($titles[$type]) . '</div>';
    foreach ($stats[$type]['orgs'] as $org => $orgData) {
        $orgLabel = h($org);
        if ($org === $myOrgName) {
            $orgLabel = '<strong>' . $orgLabel . '</strong>';
        }
        $dateStr = h(date('Y-m-d', $orgData['date']));
        if ($type === 'expiration') {
            $valueHtml = '<span class="text-warning-emphasis fw-semibold">' . $dateStr . '</span>';
        } else {
            $valueHtml = sprintf(
                '<span class="%s fw-semibold">%s <small class="text-muted">(%s)</small></span>',
                $type === 'sighting' ? 'text-success' : 'text-danger',
                (int)$orgData['count'],
                $dateStr
            );
        }
        $popLines[] = '<div class="d-flex justify-content-between gap-3"><span>'
            . $orgLabel . '</span>' . $valueHtml . '</div>';
    }
}
$popoverContent = $popLines
    ? implode('', $popLines)
    : '<span class="text-muted small">' . __('No sightings recorded') . '</span>';

$canSight = !empty($isAclSighting) && empty($attribute['is_proposal']);
$canSightValue = $canSight && !empty($me['Role']['perm_modify_org']);
$e = $count('expiration');
?>
<div class="d-flex flex-column gap-1">

    <div class="d-inline-flex align-items-center gap-1 sighting-counts"
         id="sightings_<?= $objectId ?>"
         role="button"
         tabindex="0"
         data-sighting-details="<?= $objectId ?>"
         aria-label="<?= __('Sighting details') ?>"
         data-bs-toggle="popover"
         data-bs-placement="top"
         data-bs-html="true"
         data-bs-trigger="hover focus"
         data-bs-content="<?= h($popoverContent) ?>"
         style="cursor:pointer;">
        <span class="badge rounded-pill bg-success" title="<?= __('Sightings') ?>">
            <i class="fas fa-thumbs-up me-1"></i><span class="sighting-s"><?= $count('sighting') ?></span>
        </span>
        <span class="badge rounded-pill bg-danger" title="<?= __('False positives') ?>">
            <i class="fas fa-thumbs-down me-1"></i><span class="sighting-f"><?= $count('false-positive') ?></span>
        </span>
        <?php if ($e > 0 || $isCard): ?>
        <span class="badge rounded-pill bg-warning text-dark" title="<?= __('Expirations') ?>">
            <i class="fas fa-clock me-1"></i><span class="sighting-e"><?= $e ?></span>
        </span>
        <?php endif; ?>
    </div>

    <?php if ($canSight): ?>
    <div class="btn-group btn-group-sm" role="group" aria-label="<?= __('Sightings') ?>">
        <button type="button" class="btn btn-outline-success py-0 sighting-add"
                data-attribute-id="<?= $objectId ?>" data-type="0"
                title="<?= __('Add sighting') ?>" aria-label="<?= __('Add sighting') ?>">
            <i class="far fa-thumbs-up small"></i>
        </button>
        <button type="button" class="btn btn-outline-danger py-0 sighting-add"
                data-attribute-id="<?= $objectId ?>" data-type="1"
                title="<?= __('Mark as false positive') ?>" aria-label="<?= __('Mark as false positive') ?>">
            <i class="far fa-thumbs-down small"></i>
        </button>
        <button type="button" class="btn btn-outline-secondary py-0 sighting-more"
                aria-expanded="false"
                title="<?= __('More sighting actions') ?>" aria-label="<?= __('More sighting actions') ?>">
            <i class="fas fa-ellipsis small"></i>
        </button>
        <ul class="dropdown-menu dropdown-menu-end shadow-sm small">
            <?php if ($canSightValue): ?>
            <li><h6 class="dropdown-header"><?= __('Every attribute with this value') ?></h6></li>
            <li>
                <a class="dropdown-item" href="#" data-sighting-value="<?= $objectId ?>" data-type="0">
                    <i class="far fa-thumbs-up text-success me-2"></i><?= __('Add sighting') ?>
                </a>
            </li>
            <li>
                <a class="dropdown-item" href="#" data-sighting-value="<?= $objectId ?>" data-type="1">
                    <i class="far fa-thumbs-down text-danger me-2"></i><?= __('Mark as false positive') ?>
                </a>
            </li>
            <li><hr class="dropdown-divider"></li>
            <?php endif; ?>
            <li>
                <a class="dropdown-item" href="#" data-sighting-details="<?= $objectId ?>">
                    <i class="fas fa-chart-area me-2"></i><?= __('Details & advanced sighting') ?>
                </a>
            </li>
        </ul>
    </div>
    <?php endif; ?>

</div>
