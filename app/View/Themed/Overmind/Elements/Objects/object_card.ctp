<?php
/**
 * One object as a card, for the card view of the event's object index.
 *
 * Same three pieces as the list view, stacked: the header line, the object's
 * own actions, and the attributes behind a click. The header carries exactly
 * what the accordion's header carries — on one line, truncated rather than
 * wrapped, so a grid of cards still reads as a grid of rows.
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
$objCanTag = $ctx['canTag'];
$collapseId = 'objcard_collapse_' . $objId;
$expanded = !empty($ctx['expand']);
?>


<div class="idx-card-col px-2 mb-3">
    <div class="card accordion shadow-sm idx-card<?= $isDeleted ? ' opacity-50' : '' ?>"
         style="<?= h($ctx['style']) ?>"
         data-primary-id="<?= $objId ?>">

        <!-- ── Header: the list view's header line, kept on one line ── -->
        <h2 class="accordion-header obj-header d-flex align-items-center">
            <?php if ($objCanEdit): ?>
            <span class="ps-3 pe-1 d-inline-flex align-items-center flex-shrink-0 checkbox-index">
                <input type="checkbox"
                       class="obj-select form-check-input mt-0"
                       data-object-id="<?= $objId ?>"
                       aria-label="<?= h(__('Select this object')) ?>"
                       title="<?= h(__('Select this object')) ?>">
            </span>
            <?php endif; ?>
            <button class="accordion-button<?= $expanded ? '' : ' collapsed' ?> py-2 <?= $objCanEdit ? 'ps-2 pe-3' : 'px-3' ?> rounded-top flex-grow-1"
                    style="min-width:0;"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#<?= $collapseId ?>"
                    aria-expanded="<?= $expanded ? 'true' : 'false' ?>"
                    aria-controls="<?= $collapseId ?>">

                <span class="d-flex align-items-center flex-nowrap
                             gap-2 w-100 me-2 text-start"
                      style="overflow:hidden;">

                    <!-- Distribution -->
                    <span class="flex-shrink-0 d-inline-flex">
                        <?= $this->element('genericElementsBS5/Badges/distribution', [
                            'distribution' => $object['distribution'] ?? 0,
                            'full' => false,
                        ]) ?>
                    </span>

                    <?php if ($isDeleted): ?>
                        <span class="badge bg-danger bg-opacity-75 text-white flex-shrink-0">
                            <i class="fas fa-trash me-1"></i><?= __('Deleted') ?>
                        </span>
                    <?php endif; ?>

                    <!-- Name -->
                    <span class="fw-semibold text-nowrap flex-shrink-0">
                        <span class="misp-icon misp-icon-object misp-hexagone me-1 text-secondary"></span>
                        <?= h($object['name']) ?>
                    </span>

                    <!-- First attribute's value -->
                    <?php if ($ctx['firstValue'] !== ''): ?>
                        <span class="badge bg-white border text-body fw-normal
                                     font-monospace text-truncate"
                              style="max-width:340px;min-width:0;flex-shrink:1;"
                              title="<?= h(($ctx['firstRelation'] !== ''
                                  ? $ctx['firstRelation'] . ': ' : '') . $ctx['firstValue']) ?>">
                            <?= h($ctx['firstValue']) ?>
                        </span>
                    <?php endif; ?>

                    <!-- Meta-category -->
                    <?php if (!empty($object['meta-category'])): ?>
                        <span class="badge rounded-pill text-bg-light border
                                     text-secondary fw-normal flex-shrink-0">
                            <?= h($object['meta-category']) ?>
                        </span>
                    <?php endif; ?>

                    <!-- Comment -->
                    <?php if (!empty($object['comment'])): ?>
                        <span class="text-muted fst-italic small text-truncate"
                              style="min-width:0;flex-shrink:100;"
                              title="<?= h($object['comment']) ?>">
                            <i class="fas fa-comment fa-xs me-1"></i><?= h($object['comment']) ?>
                        </span>
                    <?php endif; ?>

                    <!-- Attribute count -->
                    <span class="badge rounded-pill bg-secondary-subtle
                                 text-secondary ms-auto flex-shrink-0">
                        <?= __n('%s attribute', '%s attributes',
                            $ctx['count'], $ctx['count']) ?>
                    </span>

                    <!-- Timestamp -->
                    <span class="text-muted small text-nowrap flex-shrink-0">
                        <i class="fas fa-clock fa-xs me-1"></i>
                        <?= date('Y-m-d', (int)$object['timestamp']) ?>
                    </span>

                </span>
            </button>
        </h2>

        <!-- ── The object's own actions, right under the header ────── -->
        <div class="card-body flex-grow-0 py-2 px-3 border-top d-flex flex-wrap
                    align-items-center gap-2 small text-muted">
            <?php if (!empty($object['uuid'])): ?>
                <button type="button"
                        class="btn btn-sm btn-link p-0 text-muted lh-1"
                        title="<?= h($object['uuid']) ?>"
                        onclick="copyValueToClipboard('<?= h($object['uuid']) ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
                    <i class="fas fa-fingerprint"></i>
                </button>
            <?php endif; ?>
            <?php if (!empty($object['template_version'])): ?>
                <span class="text-nowrap">
                    <span class="misp-icon misp-icon-tag misp-hexagone me-1"></span>
                    <?= __('v%s', h($object['template_version'])) ?>
                </span>
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
             class="accordion-collapse collapse<?= $expanded ? ' show' : '' ?>">
            <?php if (!empty($attrs)): ?>
                <div class="list-group list-group-flush border-top">
                    <?php foreach ($attrs as $attr): ?>
                        <?php
                            $relation = (string)($attr['object_relation'] ?? '');
                            $label = $relation !== ''
                                ? $relation : (string)($attr['type'] ?? '');
                        ?>
                        <div class="list-group-item px-3 py-2<?= !empty($attr['deleted']) ? ' opacity-50' : '' ?>">
                            <div class="d-flex align-items-start gap-2">
                                <div class="flex-grow-1" style="min-width:0;">
                                    <div class="d-flex align-items-baseline gap-2">
                                        <span class="text-uppercase text-secondary fw-semibold text-truncate"
                                              style="font-size:.65rem;letter-spacing:.04em;"
                                              title="<?= h($label) ?>">
                                            <?= h($label) ?>
                                        </span>
                                        <span class="d-inline-flex align-items-center gap-2 flex-shrink-0">
                                            <?php if (!empty($attr['deleted'])): ?>
                                                <i class="fas fa-trash text-danger" style="font-size:.7rem;"
                                                   title="<?= h(__('Deleted')) ?>"></i>
                                            <?php endif; ?>
                                            <?= $this->element(
                                                'genericElementsBS5/IndexTable/Fields/ids',
                                                ['row' => $attr, 'field' => ['data_path' => 'to_ids']]
                                            ) ?>
                                            <?= $this->element(
                                                'genericElementsBS5/IndexTable/Fields/correlate',
                                                ['row' => $attr, 'field' => ['data_path' => 'disable_correlation']]
                                            ) ?>
                                            <?php if (!empty($attr['warnings'])): ?>
                                                <i class="fas fa-exclamation-triangle text-warning" style="font-size:.7rem;"
                                                   title="<?= h(implode(', ', array_column(
                                                       $attr['warnings'], 'warninglist_name'
                                                   ))) ?>"></i>
                                            <?php endif; ?>
                                        </span>
                                    </div>

                                    <div class="font-monospace small text-break">
                                        <?= $this->element(
                                            'genericElementsBS5/IndexTable/Fields/attribute_value',
                                            [
                                                'row'      => ['Attribute' => $attr],
                                                'field'    => ['data_path' => 'Attribute'],
                                                'viewMode' => 'card',
                                            ]
                                        ) ?>
                                    </div>

                                    <?php
                                    $chips = trim(
                                        $this->element(
                                            'genericElementsBS5/IndexTable/Fields/tag_list',
                                            [
                                                'row' => $attr,
                                                'field' => [
                                                    'data_path'       => 'AttributeTag',
                                                    'add_tag'         => $objCanTag,
                                                    'add_tag_url'     => $baseurl . '/attributes/editAttributeTags/%id%',
                                                    'add_tag_id_path' => 'id',
                                                ],
                                            ]
                                        )
                                        . $this->element(
                                            'genericElementsBS5/IndexTable/Fields/galaxy',
                                            [
                                                'row' => $attr,
                                                'field' => [
                                                    'data_path'          => 'Galaxy',
                                                    'add_galaxy'         => $objCanTag,
                                                    'add_galaxy_url'     => $baseurl . '/attributes/editAttributeGalaxies/%id%',
                                                    'add_galaxy_id_path' => 'id',
                                                ],
                                            ]
                                        )
                                    );
                                    ?>
                                    <?php if ($chips !== ''): ?>
                                        <div class="d-flex flex-wrap align-items-center gap-1 mt-1">
                                            <?= $chips ?>
                                        </div>
                                    <?php endif; ?>
                                </div>

                                <div class="flex-shrink-0">
                                    <?= $this->element('Objects/attribute_actions', [
                                        'attr' => $attr,
                                        'canEdit' => $objCanEdit,
                                        'enrichmentEnabled' => $enrichmentEnabled ?? false,
                                        'cortexEnabled' => $cortexEnabled ?? false,
                                    ]) ?>
                                </div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="border-top py-3 px-3 text-center text-muted small fst-italic">
                    <?= __('No attributes to display for this object.') ?>
                </div>
            <?php endif; ?>
        </div>

    </div>
</div>
