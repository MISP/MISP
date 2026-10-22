<?php
/**
 * One object as a card, for the card view of the event's object index.
 *
 * Same three pieces as the list view, stacked: the header line, the object's
 * own actions, and the attributes behind a click. The header is the
 * accordion's own (Objects/object_header).
 *
 * Parameters:
 *   object             array  one entry of $objects
 *   ctx                array  see $objContext in Elements/Objects/index.ctp
 *   enrichmentEnabled  bool   Plugin.Enrichment_services_enable
 *   cortexEnabled      bool   Plugin.Cortex_services_enable
 *
 * Read from the view: $baseurl, $me, $extensionEvents.
 */
$objId = $ctx['id'];
$attrs = $ctx['attrs'];
$isDeleted = $ctx['deleted'];
$objCanEdit = $ctx['canEdit'];
$objSelectable = $objCanEdit || $ctx['graphItem'] !== null;
$objCanTag = $ctx['canTag'];
$collapseId = 'objcard_collapse_' . $objId;
$expanded = !empty($ctx['expand']);
?>


<div class="idx-card-col px-2 mb-3">
    <div class="card accordion shadow-sm idx-card<?= $isDeleted ? ' opacity-50' : '' ?>"
         style="<?= h($ctx['style']) ?>"
         data-primary-id="<?= $objId ?>">

        <!-- ── Header: the same line as the list view's ── -->
        <h2 class="accordion-header obj-header d-flex align-items-center">
            <?php if ($objSelectable): ?>
            <span class="ps-3 pe-1 d-inline-flex align-items-center flex-shrink-0 checkbox-index">
                <input type="checkbox"
                       class="obj-select form-check-input mt-0"
                       data-object-id="<?= $objId ?>"
                       data-can-delete="<?= $objCanEdit ? '1' : '0' ?>"
                       <?php if ($ctx['graphItem'] !== null): ?>data-graph-item="<?= h(json_encode($ctx['graphItem'])) ?>"<?php endif; ?>
                       aria-label="<?= h(__('Select this object')) ?>"
                       title="<?= h(__('Select this object')) ?>">
            </span>
            <?php endif; ?>
            <button class="accordion-button<?= $expanded ? '' : ' collapsed' ?> py-2 <?= $objSelectable ? 'ps-2 pe-3' : 'px-3' ?> rounded-top flex-grow-1"
                    style="min-width:0;"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#<?= $collapseId ?>"
                    aria-expanded="<?= $expanded ? 'true' : 'false' ?>"
                    aria-controls="<?= $collapseId ?>">

                <?= $this->element('Objects/object_header', [
                    'object' => $object,
                    'ctx' => $ctx,
                ]) ?>
            </button>
            <?php $showRels = !empty($object['ObjectReference']) || ($objCanEdit && !$isDeleted); ?>
            <?= $this->element('Objects/object_map_button', [
                'object' => $object,
                'class' => $showRels ? 'pe-2' : '',
            ]) ?>
            <?php if ($showRels): ?>
                <?= $this->element('Objects/object_relationships', [
                    'references' => $object['ObjectReference'] ?? [],
                    'objId' => $objId,
                    'eventId' => $object['event_id'] ?? null,
                    'canEdit' => $objCanEdit && !$isDeleted,
                    'menuPrefix' => 'objCardRels',
                ]) ?>
            <?php endif; ?>
        </h2>

        <!-- ── The object's own actions, right under the header ────── -->
        <div class="card-body flex-grow-0 py-2 px-3 border-top d-flex flex-wrap
                    align-items-center gap-2 small text-muted">
            <?php if (!empty($object['comment'])): ?>
                <span class="card card-link-item bg-light w-100">
                    <div class="card-body p-1 text-truncate">
                        <i class="fas fa-comment"></i>
                        <?= h($object['comment']) ?>
                    </div>
                </span>
            <?php endif; ?>
            <?= $this->element('Objects/object_taxonomy', ['object' => $object]) ?>
            <?php if (!empty($object['uuid'])): ?>
                <button type="button"
                        class="btn btn-sm btn-link p-0 text-muted lh-1"
                        title="<?= h($object['uuid']) ?>"
                        onclick="copyValueToClipboard('<?= h($object['uuid']) ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
                    <i class="fas fa-fingerprint"></i>
                </button>
            <?php endif; ?>
            <?= $this->element('Events/View/extension_origin', [
                'event_id' => $object['event_id'] ?? 0,
                'compact' => true,
                'only_foreign' => true,
            ]) ?>

            <div class="ms-auto d-flex align-items-center gap-1">
                <?php if ($objCanEdit): ?>
                    <a href="<?= $baseurl ?>/objects/edit/<?= $objId ?>"
                       class="btn btn-sm btn-outline-secondary py-0 px-2"
                       title="<?= h(__('Edit object')) ?>"
                       onclick="event.preventDefault(); openModal('<?= $baseurl ?>/objects/edit/<?= $objId ?>');">
                        <i class="fas fa-pen-to-square"></i>
                    </a>
                    <?php
                        $delUrl = $baseurl . '/objects/delete/' . $objId
                            . ($isDeleted ? '/true' : '');
                    ?>
                    <a href="<?= $delUrl ?>"
                       class="btn btn-sm btn-outline-danger py-0 px-2"
                       title="<?= $isDeleted ? h(__('Delete permanently')) : h(__('Delete')) ?>"
                       onclick="event.preventDefault(); openModal('<?= $delUrl ?>', 'md');">
                        <i class="fas fa-trash"></i>
                    </a>
                    <?php if (!empty($enrichmentEnabled) && !$isDeleted): ?>
                        <a href="<?= $baseurl ?>/events/queryEnrichment/<?= $objId ?>/0/Enrichment/Object"
                           class="btn btn-sm btn-outline-enrichment py-0 px-2"
                           title="<?= h(__('Enrich')) ?>"
                           onclick="event.preventDefault(); openModal('<?= $baseurl ?>/events/queryEnrichment/<?= $objId ?>/0/Enrichment/Object');">
                            <i class="fas fa-wand-magic-sparkles"></i>
                        </a>
                    <?php endif; ?>
                <?php endif; ?>
                <?php if (!$isDeleted && $this->Acl->canAccess('analystGraphs', 'addNodes')): ?>
                    <a href="#" class="btn btn-sm btn-outline-analystGraph py-0 px-2" title="<?= h(__('Add to workspace')) ?>"
                       data-intel-graph-add="<?= h(json_encode([['type' => 'Object', 'uuid' => $object['uuid'], 'label' => $object['name']]])) ?>">
                        <i class="misp-icon misp-icon-analyst-graph misp-simple"></i>
                    </a>
                <?php endif; ?>
                <?php if (!$isDeleted && $this->Acl->canAccess('collectionElements', 'addElementToCollection')): ?>
                    <?php $collectUrl = $baseurl . '/collectionElements/addElementToCollection/Object/' . h($object['uuid']); ?>
                    <a href="<?= $collectUrl ?>" class="btn btn-sm btn-outline-dark py-0 px-2" title="<?= h(__('Add to collection')) ?>"
                       onclick="event.preventDefault(); openModal('<?= $collectUrl ?>', 'xl');">
                        <i class="fas fa-folder-plus"></i>
                    </a>
                <?php endif; ?>
                <?php if (!empty($me['Role']['perm_analyst_data'])): ?>
                    <?= $this->element('AnalystData/add_controls', [
                        'objectType' => 'Object',
                        'objectUuid' => $object['uuid'] ?? '',
                        'mode' => 'dropdown',
                    ]) ?>
                <?php endif; ?>
            </div>
        </div>

        <!-- ── Attributes, behind the header's click ───────────────── -->
        <div id="<?= $collapseId ?>"
             class="accordion-collapse obj-collapse collapse<?= $expanded ? ' show' : '' ?>">
            <?= $this->element('Objects/object_attribute_list', [
                'attrs' => $attrs,
                'canEdit' => $objCanEdit,
                'canTag' => $objCanTag,
                'enrichmentEnabled' => $enrichmentEnabled ?? false,
                'cortexEnabled' => $cortexEnabled ?? false,
            ]) ?>
        </div>

    </div>
</div>
