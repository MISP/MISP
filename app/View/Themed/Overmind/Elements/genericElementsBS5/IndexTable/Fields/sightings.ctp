<?php
/*
 * Sighting counts (sighting / false positive / expiration) of one attribute:
 * for a role with perm_sighting, the green and red thumbs each add a
 * sighting of their kind, and the dots open the details. The clicks are
 * handled by installSightingActions() in mispOvermind.js; the look is
 * attribute-elements.css'.
 *
 * The statistics come in two shapes: the global index passes
 * $field['sightings']['data'] keyed by attribute id, while the event view and
 * the object index carry them on the row itself, under 'Sighting'. Both are
 * keyed by 'sighting', 'false-positive' and 'expiration'.
 *
 * `readonly` (a remote event preview) draws nothing: the buttons and the
 * details go by an id that names no attribute here.
 */
$attribute = isset($row['Attribute']) ? $row['Attribute'] : $row;
if (empty($attribute['id']) || !empty($field['readonly'])) {
    return;
}

$objectId = (int)$attribute['id'];
$stats = $field['sightings']['data'][$objectId] ?? ($attribute['Sighting'] ?? []);
$stats = is_array($stats) ? $stats : [];
$count = function ($type) use ($stats) {
    return (int)($stats[$type]['count'] ?? 0);
};
$canSight = !empty($isAclSighting) && empty($attribute['is_proposal']);
$tally = [
    'sighting' => ['s', 'fas fa-thumbs-up', __('Sightings'), __('Add sighting'), 0],
    'false-positive' => ['f', 'fas fa-thumbs-down', __('False positives'), __('Mark as false positive'), 1],
    'expiration' => ['e', 'fas fa-clock', __('Expirations'), null, null],
];
?>
<div class="sighting-cell" id="sightings_<?= $objectId ?>"
     role="group" aria-label="<?= __('Sightings') ?>">
    <?php foreach ($tally as $type => list($key, $icon, $title, $addTitle, $addType)): ?>
        <?php
        $n = $count($type);
        if ($type === 'expiration' && $n === 0) {
            continue;
        }
        $class = 'btn sighting-count is-' . $key . ($n === 0 ? ' is-zero' : '');
        ?>
        <?php if ($canSight && $addTitle !== null): ?>
            <button type="button" class="<?= $class ?> sighting-add"
                    data-attribute-id="<?= $objectId ?>" data-type="<?= $addType ?>"
                    title="<?= h($addTitle) ?>" aria-label="<?= h(sprintf('%s (%s: %d)', $addTitle, $title, $n)) ?>">
                <i class="<?= $icon ?>"></i><span class="sighting-<?= $key ?>"><?= $n ?></span>
            </button>
        <?php else: ?>
            <span class="<?= $class ?>" title="<?= h($title) ?>">
                <i class="<?= $icon ?>"></i><span class="sighting-<?= $key ?>"><?= $n ?></span>
            </span>
        <?php endif; ?>
    <?php endforeach; ?>
    <button type="button" class="btn sighting-details" data-sighting-details="<?= $objectId ?>"
            title="<?= __('Sighting details') ?>" aria-label="<?= __('Sighting details') ?>">
        <i class="fas fa-ellipsis"></i>
    </button>
</div>
