<?php
/**
 * The 3-dots action menu of one object in the event's Objects tab, in the
 * table row and on the card alike. Laid out as the attribute menu
 * (Objects/attribute_actions) is, behind the index row menu's toggle.
 *
 * The `obj-row-actions` class is load-bearing: the script at the bottom of
 * Elements/Objects/index.ctp gives these toggles Popper's fixed strategy, so
 * the menu is not clipped by the table's scroll box.
 *
 * Parameters:
 *   object             array  one entry of $objects
 *   canEdit            bool   may modify the object's event
 *   mayGraph           bool   may add to a workspace
 *   mayCollect         bool   may add to a collection
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *
 * A soft-deleted object offers only Restore and Delete permanently, and no
 * menu at all to whoever may not modify its event.
 *
 * Read from the view: $baseurl, $me.
 */
$objId = (int)$object['id'];
$uuid = (string)($object['uuid'] ?? '');
$isDeleted = !empty($object['deleted']);
$canEdit = !empty($canEdit);
$mayGraph = !empty($mayGraph);
$mayCollect = !empty($mayCollect);
$editUrl = $baseurl . '/objects/edit/' . $objId;
$deleteUrl = $baseurl . '/objects/delete/' . $objId . ($isDeleted ? '/true' : '');
$enrichUrl = $baseurl . '/events/queryEnrichment/' . $objId . '/0/Enrichment/Object';
$collectUrl = $baseurl . '/collectionElements/addElementToCollection/Object/' . h($uuid);
$restoreUrl = $baseurl . '/objects/restore/' . $objId;
if ($isDeleted && !$canEdit) {
    return;
}
?>
<div class="d-inline-flex align-items-center checkbox-actions-wrapper checkbox-index">
    <div class="dropdown">
        <button class="btn btn-sm p-1 row-menu-toggle obj-row-actions"
                type="button"
                data-bs-toggle="dropdown"
                aria-expanded="false"
                title="<?= h(__('Object actions')) ?>">
            <i class="fa-solid fa-ellipsis-vertical fs-5"></i>
        </button>
        <ul class="dropdown-menu dropdown-menu-end shadow-sm">
            <?php if ($isDeleted): ?>
            <li>
                <a class="dropdown-item text-success justify-content-start" href="<?= $restoreUrl ?>"
                   onclick="event.preventDefault(); openModal('<?= $restoreUrl ?>', 'md');">
                    <i class="fas fa-rotate-left me-2"></i>
                    <?= __('Restore') ?>
                </a>
            </li>
            <li>
                <a class="dropdown-item text-danger justify-content-start" href="<?= $deleteUrl ?>"
                   onclick="event.preventDefault(); openModal('<?= $deleteUrl ?>', 'md');">
                    <i class="fas fa-trash me-2"></i>
                    <?= __('Delete permanently') ?>
                </a>
            </li>
            <?php else: ?>
            <li>
                <a class="dropdown-item justify-content-start" href="#"
                   onclick="event.preventDefault(); copyValueToClipboard('<?= h($uuid) ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
                    <i class="fas fa-copy me-2"></i>
                    <?= __('Copy UUID') ?>
                </a>
            </li>
            <?= $this->element('Objects/object_map_button', ['object' => $object]) ?>
            <?php if ($canEdit): ?>
            <li><hr class="dropdown-divider"></li>
            <li>
                <a class="dropdown-item justify-content-start" href="<?= $editUrl ?>"
                   onclick="event.preventDefault(); openModal('<?= $editUrl ?>');">
                    <i class="fas fa-pen-to-square me-2"></i>
                    <?= __('Edit') ?>
                </a>
            </li>
            <li>
                <a class="dropdown-item text-danger justify-content-start" href="<?= $deleteUrl ?>"
                   onclick="event.preventDefault(); openModal('<?= $deleteUrl ?>', 'md');">
                    <i class="fas fa-trash me-2"></i>
                    <?= __('Delete') ?>
                </a>
            </li>
            <?php endif; ?>
            <?php if ($canEdit && !empty($enrichmentEnabled)): ?>
            <li><hr class="dropdown-divider"></li>
            <li>
                <a class="dropdown-item justify-content-start" href="<?= $enrichUrl ?>"
                   onclick="event.preventDefault(); openModal('<?= $enrichUrl ?>');">
                    <i class="fas fa-wand-magic-sparkles text-enrichment me-2"></i>
                    <?= __('Enrich') ?>
                </a>
            </li>
            <?php endif; ?>
            <?= $this->element('AnalystData/add_controls', [
                'objectType' => 'Object',
                'objectUuid' => $uuid,
                'mode' => 'menu_items',
                'showView' => false,
            ]) ?>
            <?php if ($mayGraph || $mayCollect): ?>
            <li><hr class="dropdown-divider"></li>
            <?php endif; ?>
            <?php if ($mayGraph): ?>
            <li>
                <a class="dropdown-item justify-content-start" href="#"
                   data-intel-graph-add="<?= h(json_encode([['type' => 'Object', 'uuid' => $uuid, 'label' => $object['name']]])) ?>">
                    <i class="text-analystGraph misp-icon misp-icon-analyst-graph misp-simple me-2"></i>
                    <?= __('Add to workspace') ?>
                </a>
            </li>
            <?php endif; ?>
            <?php if ($mayCollect): ?>
            <li>
                <a class="dropdown-item justify-content-start" href="<?= $collectUrl ?>"
                   onclick="event.preventDefault(); openModal('<?= $collectUrl ?>', 'xl');">
                    <i class="fas fa-folder-plus me-2"></i>
                    <?= __('Add to collection') ?>
                </a>
            </li>
            <?php endif; ?>
            <?php endif; ?>
        </ul>
    </div>
</div>
