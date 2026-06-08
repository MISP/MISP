<?php
/*
 *
 * Displays sighting counts (sighting / false-positive / expiration) for an
 * attribute with a per-org popover breakdown and optional add-sighting buttons.
 *
 */
$isCard    = isset($viewMode) && $viewMode === 'card';

$isEventView = !isset($row['Attribute']);
if ($isEventView) {
    // In event context, $row is already the Attribute array
    $attribute = $row;
} else {
    // In global index context, $row contains an 'Attribute' key
    $attribute = isset($row['Attribute']) ? $row['Attribute'] : null;
}
if (!$attribute || !isset($attribute['id'])) return;

$objectId       = intval($attribute['id']);
$sightingsAll   = isset($field['sightings']['data']) ? $field['sightings']['data'] : [];
$objectSighting = isset($sightingsAll[$objectId])    ? $sightingsAll[$objectId]    : [];

if ($isEventView) {
    $s = isset($attribute['Sighting']['sighting']['count'])      ? intval($attribute['Sighting']['sighting']['count']) : 0;
    $f = isset($attribute['Sighting']['false_positive']['count'])? intval($attribute['Sighting']['false_positive']['count']) : 0;
    $e = isset($attribute['Sighting']['expiration']['count'])     ? intval($attribute['Sighting']['expiration']['count']) : 0;
} else {
    $s = isset($objectSighting['sighting']['count'])       ? intval($objectSighting['sighting']['count'])       : 0;
    $f = isset($objectSighting['false-positive']['count']) ? intval($objectSighting['false-positive']['count']) : 0;
    $e = isset($objectSighting['expiration']['count'])     ? intval($objectSighting['expiration']['count'])     : 0;
}

/* Popover content: per-org breakdown */
$myOrgName = isset($me['Organisation']['name']) ? $me['Organisation']['name'] : '';
$popLines  = [];

foreach ($objectSighting as $type => $typeData) {
    $typeName = ($type !== 'expiration')
        ? Inflector::pluralize($type)
        : $type;
    $popLines[] = '<div class="fw-semibold small mt-1 mb-1">' . ucfirst(h($typeName)) . '</div>';

    foreach ($typeData['orgs'] as $org => $orgData) {
        $isMine    = ($org === $myOrgName);
        $dateStr   = date('Y-m-d', $orgData['date']);
        $orgLabel  = ($isMine ? '<strong>' : '') . h($org) . ($isMine ? '</strong>' : '');

        if ($type === 'expiration') {
            $valueHtml = '<span class="text-warning fw-semibold">' . h($dateStr) . '</span>';
        } else {
            $colorClass = ($type === 'sighting') ? 'text-success' : 'text-danger';
            $valueHtml  = '<span class="' . $colorClass . ' fw-semibold">'
                        . h($orgData['count']) . ' <small class="text-muted">(' . h($dateStr) . ')</small>'
                        . '</span>';
        }

        $popLines[] = '<div class="d-flex justify-content-between gap-3">'
                    . '<span>' . $orgLabel . '</span>'
                    . $valueHtml
                    . '</div>';
    }
}

$popoverContent = !empty($popLines)
    ? implode('', $popLines)
    : '<span class="text-muted small">' . __('No sightings recorded') . '</span>';
?>

<div class="d-flex flex-column gap-1">

    <!-- ── Count pills ── -->
    <div class="d-inline-flex align-items-center gap-1 sighting-counts"
         id="sightings_<?= $objectId ?>"
         data-attribute-id="<?= $objectId ?>"
         data-bs-toggle="popover"
         data-bs-placement="top"
         data-bs-html="true"
         data-bs-trigger="hover focus"
         data-bs-content="<?= h($popoverContent) ?>"
         style="cursor:default;">

        <span class="badge rounded-pill bg-success"
              title="<?= __('Sightings') ?>">
            <i class="fas fa-thumbs-up me-1"></i>
            <span class="sighting-s"><?= $s ?></span>
        </span>

        <span class="badge rounded-pill bg-danger"
              title="<?= __('False positives') ?>">
            <i class="fas fa-thumbs-down me-1"></i>
            <span class="sighting-f"><?= $f ?></span>
        </span>

        <?php if ($e > 0 || $isCard): ?>
        <span class="badge rounded-pill bg-warning text-dark"
              title="<?= __('Expirations') ?>">
            <i class="fas fa-clock me-1"></i>
            <span class="sighting-e"><?= $e ?></span>
        </span>
        <?php endif; ?>

    </div>

    <!-- ── Action buttons ── -->
    <?php if (!empty($isAclSighting)): ?>
    <div class="d-flex gap-1">

        <button class="btn btn-outline-success btn-sm py-0 add-sighting-btn"
                data-attribute-id="<?= $objectId ?>"
                data-type="0"
                title="<?= __('Add sighting') ?>"
                aria-label="<?= __('Add sighting') ?>">
            <i class="far fa-thumbs-up small"></i>
        </button>

        <button class="btn btn-outline-danger btn-sm py-0 add-sighting-btn"
                data-attribute-id="<?= $objectId ?>"
                data-type="1"
                title="<?= __('Mark as false positive') ?>"
                aria-label="<?= __('Mark as false positive') ?>">
            <i class="far fa-thumbs-down small"></i>
        </button>

        <button class="btn btn-outline-secondary btn-sm py-0"
                title="<?= __('Advanced sightings') ?>"
                aria-label="<?= __('Advanced sightings') ?>"
                onclick="openModal('<?= $baseurl ?>/sightings/advanced/<?= $objectId ?>/attribute', 'lg')">
            <i class="fas fa-sliders small"></i>
        </button>

    </div>
    <?php endif; ?>

</div>

<!-- i18n for JS -->
<script>
window._sightingI18n = {
    addedSighting: <?= json_encode(__('Sighting added')) ?>,
    addedFP:       <?= json_encode(__('Marked as false positive')) ?>,
    failed:        <?= json_encode(__('Failed to add sighting')) ?>,
    reqFailed:     <?= json_encode(__('Request failed — please try again')) ?>,
};
</script>
