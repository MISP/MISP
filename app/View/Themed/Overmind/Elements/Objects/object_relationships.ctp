<?php
/**
 * The relationship count an object carries, in its card header.
 *
 * Hovering names them, and each one in the menu links to what it points at.
 * Rendered outside the accordion button so a click reaches the target instead
 * of collapsing the card.
 *
 * Parameters:
 *   references  array  the object's ObjectReference rows
 *   objId       int
 *   eventId     int|null
 */
$count = count($references);

$describe = function ($reference) {
    $type = $reference['relationship_type'] !== ''
        ? $reference['relationship_type']
        : __('related to');
    // referenced_type: 0 is an attribute, 1 an object.
    $kind = (int)$reference['referenced_type'] === 1 ? __('object') : __('attribute');
    return $type . ' → ' . $kind . ' ' . substr((string)$reference['referenced_uuid'], 0, 8);
};

$summary = [];
foreach ($references as $reference) {
    $summary[] = $describe($reference);
}
$menuId = 'objRels' . h($objId);
?>
<div class="dropdown flex-shrink-0 pe-3">
    <button type="button"
            class="btn btn-sm ov-obj-rel-badge"
            id="<?= $menuId ?>"
            data-bs-toggle="dropdown"
            aria-expanded="false"
            title="<?= h(implode("\n", $summary)) ?>">
        <i class="fas fa-link"></i>
        <?= $count ?>
    </button>
    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="<?= $menuId ?>">
        <li><h6 class="dropdown-header"><?= __n('%s relationship', '%s relationships', $count, $count) ?></h6></li>
        <?php foreach ($references as $reference): ?>
            <?php
            $isObject = (int)$reference['referenced_type'] === 1;
            $target = $isObject
                ? $baseurl . '/objects/view/' . h($reference['referenced_id'])
                : $baseurl . '/events/view2/' . h($eventId)
                    . '/searchFor:' . h($reference['referenced_uuid']) . '#tab-attributes';
            ?>
            <li>
                <a class="dropdown-item d-flex align-items-center gap-2"
                   href="<?= $target ?>">
                    <span class="badge bg-object"><?= h($reference['relationship_type']) ?></span>
                    <span class="text-muted small"><?= $isObject ? __('object') : __('attribute') ?></span>
                    <code class="small"><?= h(substr((string)$reference['referenced_uuid'], 0, 8)) ?></code>
                    <?php if (!empty($reference['comment'])): ?>
                        <span class="text-muted fst-italic small text-truncate">
                            <?= h($reference['comment']) ?>
                        </span>
                    <?php endif; ?>
                </a>
            </li>
        <?php endforeach; ?>
    </ul>
</div>
