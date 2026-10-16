<?php
/**
 * The relationship count an object carries, in its card header.
 *
 * Hovering names them, and each one in the menu links to what it points at.
 * Rendered outside the accordion button so a click reaches the target instead
 * of collapsing the card.
 *
 * Parameters:
 *   references  array  the object's ObjectReference rows, each with its Target
 *   objId       int
 *   eventId     int|null
 *   canEdit     bool   may add and delete relationships
 *   menuPrefix  string id prefix, unique per rendering of the object list
 */
$count = count($references);
$canEdit = !empty($canEdit);

$targetLabel = function ($reference) {
    if (!empty($reference['Target'])) {
        return $reference['Target']['label'];
    }
    return substr((string)$reference['referenced_uuid'], 0, 8);
};

$summary = [];
foreach ($references as $reference) {
    $type = $reference['relationship_type'] !== '' ? $reference['relationship_type'] : __('related to');
    $summary[] = $type . ' → ' . $targetLabel($reference);
}
$menuId = ($menuPrefix ?? 'objRels') . (int)$objId;
$addUrl = $baseurl . '/objectReferences/add/' . (int)$objId;
?>
<div class="dropdown flex-shrink-0 pe-3">
    <button type="button"
            class="btn btn-sm ov-obj-rel-badge<?= $count === 0 ? ' ov-obj-rel-empty' : '' ?>"
            id="<?= $menuId ?>"
            data-bs-toggle="dropdown"
            data-bs-auto-close="outside"
            aria-expanded="false"
            title="<?= h($count ? implode("\n", $summary) : __('Add a relationship')) ?>">
        <i class="fas fa-link"></i>
        <?= $count ?: '<i class="fas fa-plus"></i>' ?>
    </button>
    <ul class="dropdown-menu dropdown-menu-end ov-obj-rel-menu" aria-labelledby="<?= $menuId ?>">
        <li><h6 class="dropdown-header"><?= __n('%s relationship', '%s relationships', $count, $count) ?></h6></li>
        <?php foreach ($references as $reference): ?>
            <?php
            $target = $reference['Target'] ?? null;
            $isObject = (int)$reference['referenced_type'] === 1;
            $targetEventId = $target['event_id'] ?? $eventId;
            $href = $isObject
                ? $baseurl . '/objects/view/' . h($target['id'] ?? $reference['referenced_id'])
                : $baseurl . '/events/view/' . h($targetEventId)
                    . '/searchFor:' . h($reference['referenced_uuid']) . '#tab-attributes';
            ?>
            <li class="d-flex align-items-center ov-obj-rel-item" data-reference-id="<?= (int)($reference['id'] ?? 0) ?>">
                <a class="dropdown-item d-flex align-items-center gap-2 flex-grow-1" href="<?= $href ?>"
                   title="<?= h($reference['referenced_uuid']) ?>">
                    <span class="badge bg-object flex-shrink-0"><?= h($reference['relationship_type']) ?></span>
                    <i class="<?= $isObject ? 'misp-icon misp-icon-object' : 'misp-icon misp-icon-attribute' ?> misp-simple text-muted flex-shrink-0"
                       title="<?= $isObject ? __('Object') : __('Attribute') ?>"></i>
                    <span class="d-flex flex-column ov-obj-rel-target">
                        <span class="text-truncate<?= $target ? '' : ' font-monospace' ?>"><?= h($targetLabel($reference)) ?></span>
                        <?php if ($target || !empty($reference['comment'])): ?>
                            <span class="text-muted small text-truncate">
                                <?= h(implode(' · ', array_filter([
                                    $target['context'] ?? null,
                                    ($target && (int)$target['event_id'] !== (int)$eventId)
                                        ? __('Event #%s', $target['event_id']) : null,
                                    $reference['comment'] ?? null,
                                ]))) ?>
                            </span>
                        <?php endif; ?>
                    </span>
                </a>
                <?php if ($canEdit && !empty($reference['id'])): ?>
                    <button type="button" class="btn btn-sm ov-obj-rel-delete me-2"
                            data-delete-url="<?= h($baseurl . '/objectReferences/delete/' . (int)$reference['id']) ?>"
                            data-reference-label="<?= h($reference['relationship_type'] . ' → ' . $targetLabel($reference)) ?>"
                            title="<?= h(__('Delete this relationship')) ?>"
                            aria-label="<?= h(__('Delete this relationship')) ?>">
                        <i class="fas fa-trash"></i>
                    </button>
                <?php endif; ?>
            </li>
        <?php endforeach; ?>
        <?php if ($canEdit): ?>
            <?php if ($count): ?><li><hr class="dropdown-divider"></li><?php endif; ?>
            <li>
                <a class="dropdown-item d-flex align-items-center gap-2" href="<?= h($addUrl) ?>"
                   onclick="event.preventDefault(); openModal('<?= h($addUrl) ?>', 'lg');">
                    <i class="fas fa-plus text-object"></i><?= __('Add relationship') ?>
                </a>
            </li>
        <?php endif; ?>
    </ul>
</div>
