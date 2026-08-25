<?php
App::uses('DistributionLevel', 'Tools');

$eventId   = $event['Event']['id'];
$total     = (int)($total ?? 0);
$page      = (int)($page  ?? 1);
$limit     = (int)($limit ?? 60);
$totalPages = $limit > 0 ? (int)ceil($total / $limit) : 1;
$window     = 2;
$objectsUrl = '/events/viewObjects/' . $eventId;

$namedParams     = $this->request->params['named'] ?? [];
$currentDeleted  = (int)($namedParams['deleted'] ?? 0);
$currentProposal = (int)($namedParams['proposal'] ?? 0);
$toggleDeleted   = $currentDeleted ? 0 : 1;
$toggleProposal  = $currentProposal ? 0 : 1;
// Fallback hrefs (the JS rebuilds the real URL); each preserves the other toggle.
$toggleUrl       = $baseurl . $objectsUrl
    . ($toggleDeleted ? '/deleted:' . $toggleDeleted : '')
    . ($currentProposal ? '/proposal:' . $currentProposal : '');
$proposalUrl     = $baseurl . $objectsUrl
    . ($currentDeleted ? '/deleted:' . $currentDeleted : '')
    . ($toggleProposal ? '/proposal:' . $toggleProposal : '');

$canEdit = isset($event)
    ? $this->Acl->canModifyEvent($event)
    : false;

// Tag/galaxy "+" buttons on object attributes follow the event's tag-modify
// rights (galaxy clusters are attached as tags, so they share the permission).
$canTagObj = isset($event)
    ? $this->Acl->canModifyTag($event)
    : false;

$_enrichmentEnabled = (bool)Configure::read('Plugin.Enrichment_services_enable');
$_cortexEnabled = (bool)Configure::read('Plugin.Cortex_services_enable');

// Inline helper: render a small distribution badge. A named function has no
// $this, so the lib is called statically rather than through the helper.
function _objDistBadge($dist) {
    $c = DistributionLevel::get($dist);
    return sprintf(
        '<span class="badge d-inline-flex align-items-center px-2 py-1"'
        . ' style="background:%s;color:%s;border:1px solid %s20;font-weight:500;">'
        . '<i class="%s"></i></span>',
        h($c['bg']), h($c['color']), h($c['color']), h($c['icon'])
    );
}
?>

<div id="objectListContainer" class="container-fluid px-0">

    <!-- ── Filter bar (same card structure as scaffold) ──── -->
    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <?= $this->element(
                'genericElementsBS5/IndexTable/filter_bar',
                [
                    'scaffold_data' => [
                        'filter_bar' => [
                            'children' => [
                                [
                                    'type'        => 'search',
                                    'button'      => __('Search'),
                                    'placeholder' => __('Filter objects…'),
                                    'mode'        => 'legacy',
                                    'name'        => 'searchFor',
                                ],
                                [
                                    'type'  => 'button',
                                    'url'   => $proposalUrl,
                                    'class' => 'btn obj-proposal-toggle '. ($currentProposal ? 'btn-warning' : 'btn-outline-warning'),
                                    'icon'  => 'fas fa-comment-dots',
                                    'label' => __('Proposals') . (!empty($proposalCount) ? ' (' . (int)$proposalCount . ')' : ''),
                                ],
                                [
                                    'type'  => 'button',
                                    'url'   => $toggleUrl,
                                    'class' => 'btn obj-deleted-toggle '. ($currentDeleted ? 'btn-danger' : 'btn-outline-danger'),
                                    'icon'  => 'fas fa-trash',
                                    'label' => __('Deleted') . (!empty($deletedCount) ? ' (' . (int)$deletedCount . ')' : ''),
                                ],
                            ],
                        ],
                    ],
                    'item_url' => $objectsUrl,
                ]
            ) ?>
            <?php if ($canEdit): ?>
            <div id="multiSelectToolbar" class="mt-2 d-none">
                <div class="p-2 border rounded bg-light d-flex align-items-center gap-2 flex-wrap">
                    <strong>
                        <?= __('Selected items') ?>:
                        <span id="selectedCount">0</span>
                    </strong>
                    <button id="multi-delete-button"
                            class="btn btn-danger btn-sm d-none"
                            title="<?= __('Delete selected attributes') ?>"
                            aria-label="<?= __('Delete selected attributes') ?>"
                            onclick="multiSelectItems(baseurl + '/attributes/deleteSelection', '')">
                        <i class="fas fa-trash text-white"></i>
                        <span class="text-white"> <?= __('Delete') ?></span>
                    </button>
                </div>
            </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- ── Object cards ────────────────────────────────────── -->
    <?php if (!empty($objects)): ?>
        <div class="accordion" id="objectAccordion">
        <?php foreach ($objects as $idx => $object): ?>
        <?php
            $objId       = (int)$object['id'];
            $collapseId  = 'obj_collapse_' . $objId;
            $headingId   = 'obj_heading_'  . $objId;
            $attrCount   = count($object['Attribute'] ?? []);
            // Auto-expand objects that carry a proposal while the Proposals
            // toggle is on, so toggling it open/closes every object with a
            // pending proposal.
            $hasProposal = false;
            foreach (($object['Attribute'] ?? []) as $_a) {
                if (!empty($_a['ShadowAttribute'])) { $hasProposal = true; break; }
            }
            $expandForProposal = $currentProposal && $hasProposal;
        ?>

        <?php $isDeleted = !empty($object['deleted']); ?>
        <div class="accordion-item shadow-sm mb-2 rounded border<?= $isDeleted ? ' opacity-50' : '' ?>"
             data-primary-id="<?= $objId ?>">

            <!-- Card header -->
            <h2 class="accordion-header" id="<?= $headingId ?>">
                <button class="accordion-button<?= $expandForProposal ? '' : ' collapsed' ?> py-2 px-3 rounded"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#<?= $collapseId ?>"
                        aria-expanded="<?= $expandForProposal ? 'true' : 'false' ?>"
                        aria-controls="<?= $collapseId ?>">

                    <span class="d-flex align-items-center
                                 flex-wrap gap-2 w-100 me-2">

                        <!-- Distribution -->
                        <?= _objDistBadge($object['distribution'] ?? 0) ?>

                        <?php if ($isDeleted): ?>
                        <span class="badge bg-danger bg-opacity-75 text-white">
                            <i class="fas fa-trash me-1"></i><?= __('Deleted') ?>
                        </span>
                        <?php endif; ?>

                        <!-- Name -->
                        <span class="fw-semibold">
                            <span class="misp-icon misp-icon-object misp-hexagone me-1 text-secondary"></span>
                            <?= h($object['name']) ?>
                        </span>

                        <!-- Meta-category -->
                        <?php if (!empty($object['meta-category'])): ?>
                            <span class="badge rounded-pill text-bg-light
                                         border text-secondary fw-normal">
                                <?= h($object['meta-category']) ?>
                            </span>
                        <?php endif; ?>

                        <!-- Comment (truncated) -->
                        <?php if (!empty($object['comment'])): ?>
                            <span class="text-muted fst-italic small
                                         text-truncate" style="max-width:500px;">
                                <i class="fas fa-comment fa-xs me-1"></i>
                                <?= h($object['comment']) ?>
                            </span>
                        <?php endif; ?>

                        <!-- Attribute count chip -->
                        <span class="badge rounded-pill bg-secondary-subtle
                                     text-secondary ms-auto">
                            <?= __n(
                                '%s attribute',
                                '%s attributes',
                                $attrCount, $attrCount
                            ) ?>
                        </span>

                        <!-- Timestamp -->
                        <span class="text-muted small text-nowrap">
                            <i class="fas fa-clock fa-xs me-1"></i>
                            <?= date('Y-m-d', (int)$object['timestamp']) ?>
                        </span>

                    </span>

                </button>
            </h2>

            <!-- Card body -->
            <div id="<?= $collapseId ?>"
                 class="accordion-collapse collapse<?= $expandForProposal ? ' show' : '' ?>"
                 aria-labelledby="<?= $headingId ?>">

                <div class="accordion-body p-0">

                    <!-- Object meta row -->
                    <?php if (
                        !empty($object['description'])
                        || !empty($object['uuid'])
                        || !empty($object['first_seen'])
                        || !empty($object['last_seen'])
                        || $canEdit

                    ): ?>
                    <div class="px-3 py-2 bg-light border-bottom
                                d-flex flex-wrap align-items-center gap-3 small text-muted">
                        <?php if (!empty($object['uuid'])): ?>
                            <span class="d-inline-flex align-items-center gap-1">
                                <i class="fas fa-fingerprint me-1"></i>
                                <code class="user-select-all">
                                    <?= h($object['uuid']) ?>
                                </code>
                                <button type="button"
                                        class="btn btn-sm btn-link p-0 text-muted lh-1"
                                        title="<?= h(__('Copy UUID')) ?>"
                                        onclick="copyValueToClipboard('<?= h($object['uuid']) ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
                                    <i class="fas fa-copy"></i>
                                </button>
                            </span>
                        <?php endif; ?>
                        <?php
                            $fmtSeen = function ($value) {
                                $dt = date_create((string)$value);
                                if ($dt === false) {
                                    return ['date' => (string)$value, 'time' => ''];
                                }
                                return [
                                    'date' => $dt->format('Y-m-d'),
                                    'time' => $dt->format('H:i:s'),
                                ];
                            };
                        ?>
                        <?php if (!empty($object['first_seen'])): $fs = $fmtSeen($object['first_seen']); ?>
                            <span class="d-inline-flex align-items-center gap-1"
                                  title="<?= h($object['first_seen']) ?>">
                                <i class="fas fa-calendar-plus text-secondary"></i>
                                <span class="text-uppercase fw-semibold"
                                      style="font-size:.65rem;letter-spacing:.04em;"><?= __('First seen') ?></span>
                                <span class="badge bg-white border text-secondary fw-normal font-monospace">
                                    <?= h($fs['date']) ?><?php if ($fs['time'] !== ''): ?><span class="text-muted ms-1"><?= h($fs['time']) ?></span><?php endif; ?>
                                </span>
                            </span>
                        <?php endif; ?>
                        <?php if (!empty($object['last_seen'])): $ls = $fmtSeen($object['last_seen']); ?>
                            <span class="d-inline-flex align-items-center gap-1"
                                  title="<?= h($object['last_seen']) ?>">
                                <i class="fas fa-calendar-check text-secondary"></i>
                                <span class="text-uppercase fw-semibold"
                                      style="font-size:.65rem;letter-spacing:.04em;"><?= __('Last seen') ?></span>
                                <span class="badge bg-white border text-secondary fw-normal font-monospace">
                                    <?= h($ls['date']) ?><?php if ($ls['time'] !== ''): ?><span class="text-muted ms-1"><?= h($ls['time']) ?></span><?php endif; ?>
                                </span>
                            </span>
                        <?php endif; ?>
                        <?php if (!empty($object['template_version'])): ?>
                            <span>
                                <span class="misp-icon misp-icon-tag misp-hexagone me-1"></span>
                                <?= __('Template v%s',
                                    h($object['template_version'])) ?>
                            </span>
                        <?php endif; ?>

                        <?php if ($canEdit): ?>
                            <a href="<?= $baseurl ?>/objects/edit/<?= $objId ?>"
                            onclick="event.preventDefault(); openModal('<?= $baseurl ?>/objects/edit/<?= $objId ?>');"
                            class="btn btn-sm btn-outline-secondary ms-auto">
                                <i class="fas fa-pen-to-square me-1"></i>
                                <?= __('Edit') ?>
                            </a>
                            <?php
                                $delUrl   = $baseurl . '/objects/delete/' . $objId . ($isDeleted ? '/true' : '');
                                $delLabel = $isDeleted ? __('Delete permanently') : __('Delete');
                            ?>
                            <a href="<?= $delUrl ?>"
                            class="btn btn-sm btn-outline-danger"
                            onclick="event.preventDefault(); openModal('<?= $delUrl ?>', 'sm');">
                                <i class="fas fa-trash me-1"></i>
                                <?= $delLabel ?>
                            </a>
                            <?php if ($_enrichmentEnabled && !$isDeleted): ?>
                                <a href="<?= $baseurl ?>/events/queryEnrichment/<?= $objId ?>/0/Enrichment/Object"
                                   class="btn btn-sm btn-outline-enrichment"
                                   onclick="event.preventDefault(); openModal('<?= $baseurl ?>/events/queryEnrichment/<?= $objId ?>/0/Enrichment/Object');">
                                    <i class="fas fa-wand-magic-sparkles me-1"></i>
                                    <?= __('Enrich') ?>
                                </a>
                            <?php endif; ?>
                        <?php endif; ?>
                        <?php if (!empty($me['Role']['perm_analyst_data'])): ?>
                            <div class="<?= $canEdit ? '' : 'ms-auto' ?>">
                                <?= $this->element('AnalystData/add_controls', [
                                    'objectType' => 'Object',
                                    'objectUuid' => $object['uuid'] ?? '',
                                    'mode' => 'dropdown',
                                ]) ?>
                            </div>
                        <?php endif; ?>
                    </div>
                    <?php endif; ?>


                    <!-- Attribute table -->
                    <?php if (!empty($object['Attribute'])): ?>
                    <div class="table-responsive">
                        <table class="table table-sm table-hover
                                      align-middle mb-0">
                            <thead class="table-light">
                                <tr>
                                    <th class="ps-3" style="width:1%"></th>
                                    <th style="width:30%"><?= __('Value') ?></th>
                                    <th style="width:10%"><?= __('Type') ?></th>
                                    <th style="width:10%"><?= __('Category') ?></th>
                                    <th style="width:15%"><?= __('Tags') ?></th>
                                    <th style="width:15%"><?= __('Galaxies') ?></th>
                                    <th class="text-center"><?= __('IDS') ?></th>
                                    <th class="text-center"><?= __('Correlate') ?></th>
                                    <th style="width:10%"><?= __('Related Events') ?></th>
                                    <th style="width:10%"><?= __('Feed Hits') ?></th>
                                    <th style="width:8%"><?= __('Sightings') ?></th>
                                    <th class="pe-3" style="width:1%"></th>
                                </tr>
                            </thead>
                            <tbody>
                            <?php foreach (
                                $object['Attribute'] as $attr
                            ): ?>
                            <?php $attrId = (int)$attr['id']; ?>
                                <tr data-primary-id="<?= $attrId ?>"<?php if (
                                    !empty($attr['deleted'])
                                ): ?> class="text-decoration-line-through
                                             text-muted opacity-50"<?php
                                endif; ?>>

                                    <!-- Checkbox -->
                                    <td class="ps-3">
                                        <div class="d-inline-flex align-items-center
                                                    checkbox-actions-wrapper
                                                    checkbox-index">
                                            <input
                                                type="checkbox"
                                                class="item-checkbox form-check-input
                                                       mass-select mt-0"
                                                data-item-id="<?= $attrId ?>"
                                                data-can-delete="<?= $canEdit ? '1' : '0' ?>"
                                            >
                                        </div>
                                    </td>

                                    <!-- Value: distribution badge + value + comment via attribute_value -->
                                    <td class="text-break">
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/attribute_value',
                                            [
                                                'row'   => ['Attribute' => $attr],
                                                'field' => ['data_path' => 'Attribute'],
                                            ]
                                        ); ?>
                                        <?php if (!empty($attr['warnings'])): ?>
                                            <i class="fas fa-exclamation-triangle
                                                       text-warning ms-1"
                                               title="<?= h(implode(', ', array_column(
                                                   $attr['warnings'],
                                                   'warninglist_name'
                                               ))) ?>"></i>
                                        <?php endif; ?>
                                    </td>

                                    <!-- Category + Relation (merged) -->
                                    <td>
                                        <div class="d-flex align-items-center gap-1">
                                            <?php echo $this->element(
                                                'genericElementsBS5/Badges/category',
                                                ['category' => $attr['category'] ?? '']
                                            ); ?>
                                            <?php if (!empty($attr['object_relation'])): ?>
                                                <span class="d-inline-flex align-items-center">
                                                    <p class="border border-dark rounded p-1 mb-0
                                                               bg-dark text-white"
                                                       style="font-size:inherit;">
                                                        <?= h($attr['object_relation']) ?>
                                                    </p>
                                                </span>
                                            <?php endif; ?>
                                        </div>
                                    </td>

                                    <!-- Type -->
                                    <td>
                                        <?php echo $this->element(
                                            'genericElementsBS5/Badges/type',
                                            ['type' => $attr['type'] ?? '']
                                        ); ?>
                                    </td>

                                    <!-- Tags -->
                                    <td>
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/tag_list',
                                            [
                                                'row'   => $attr,
                                                'field' => [
                                                    'data_path'       => 'AttributeTag',
                                                    'add_tag'         => $canTagObj,
                                                    'add_tag_url'     => $baseurl . '/attributes/editAttributeTags/%id%',
                                                    'add_tag_id_path' => 'id',
                                                ],
                                            ]
                                        ); ?>
                                    </td>


                                    <!-- Galaxies -->
                                    <td>
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/galaxy',
                                            [
                                                'row'   => $attr,
                                                'field' => [
                                                    'data_path'          => 'Galaxy',
                                                    'add_galaxy'         => $canTagObj,
                                                    'add_galaxy_url'     => $baseurl . '/attributes/editAttributeGalaxies/%id%',
                                                    'add_galaxy_id_path' => 'id',
                                                ],
                                            ]
                                        ); ?>
                                    </td>

                                    <!-- IDS (interactive via ids.ctp) -->
                                    <td class="text-center">
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/ids',
                                            [
                                                'row'   => $attr,
                                                'field' => ['data_path' => 'to_ids'],
                                            ]
                                        ); ?>
                                    </td>

                                    <!-- Correlate (interactive via correlate.ctp) -->
                                    <td class="text-center">
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/correlate',
                                            [
                                                'row'   => $attr,
                                                'field' => ['data_path' => 'disable_correlation'],
                                            ]
                                        ); ?>
                                    </td>

                                    <!-- Related Events -->
                                    <td>
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/relatedEvents',
                                            [
                                                'row'   => $attr,
                                                'field' => [],
                                            ]
                                        ); ?>
                                    </td>

                                    <!-- Feed Hits -->
                                    <td>
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/feedHits',
                                            [
                                                'row'   => ['Attribute' => $attr],
                                                'field' => [],
                                            ]
                                        ); ?>
                                    </td>

                                    <!-- Sightings -->
                                    <td>
                                        <?php echo $this->element(
                                            'genericElementsBS5/IndexTable/Fields/sightings',
                                            [
                                                'row'   => $attr,
                                                'field' => [
                                                    'sightings' => [
                                                        'data' => [],
                                                        'csv'  => [],
                                                    ],
                                                ],
                                            ]
                                        ); ?>
                                    </td>

                                    <!-- Actions (3-dots dropdown) -->
                                    <td class="pe-3">
                                        <div class="d-inline-flex align-items-center
                                                    checkbox-actions-wrapper
                                                    checkbox-index">
                                            <div class="dropdown">
                                                <button
                                                    class="btn btn-sm btn-light p-1"
                                                    type="button"
                                                    data-bs-toggle="dropdown"
                                                    aria-expanded="false">
                                                    <i class="fa-solid fa-ellipsis-vertical fs-5"></i>
                                                </button>
                                                <ul class="dropdown-menu
                                                           dropdown-menu-end
                                                           shadow-sm">
                                                    <li>
                                                        <a class="dropdown-item justify-content-start"
                                                           href="#"
                                                           onclick="event.preventDefault(); copyValueToClipboard('<?= h($attr['uuid'] ?? '') ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
                                                            <i class="fas fa-copy me-2"></i>
                                                            <?= __('Copy UUID') ?>
                                                        </a>
                                                    </li>
                                                    <?php if (!empty($me['Role']['perm_add']) && empty($attr['deleted'])): ?>
                                                    <li>
                                                        <a class="dropdown-item justify-content-start"
                                                           href="#"
                                                           onclick="event.preventDefault(); openModal('<?= $baseurl ?>/shadow_attributes/edit/<?= $attrId ?>');">
                                                            <i class="fas fa-comment-dots me-2"></i>
                                                            <?= __('Propose change') ?>
                                                        </a>
                                                    </li>
                                                    <?php endif; ?>
                                                    <?php if ($canEdit && $_enrichmentEnabled && empty($attr['deleted'])): ?>
                                                    <li>
                                                        <a class="dropdown-item justify-content-start"
                                                           href="#"
                                                           onclick="event.preventDefault(); openModal('<?= $baseurl ?>/events/queryEnrichment/<?= $attrId ?>/0/Enrichment/Attribute');">
                                                            <i class="fas fa-wand-magic-sparkles text-enrichment me-2"></i>
                                                            <?= __('Enrich') ?>
                                                        </a>
                                                    </li>
                                                    <?php endif; ?>
                                                    <?php if ($canEdit && $_cortexEnabled && empty($attr['deleted'])): ?>
                                                    <li>
                                                        <a class="dropdown-item justify-content-start"
                                                           href="#"
                                                           onclick="event.preventDefault(); openModal('<?= $baseurl ?>/events/queryEnrichment/<?= $attrId ?>/0/Cortex/Attribute');">
                                                            <i class="fas fa-eye me-2"></i>
                                                            <?= __('Enrich (Cortex)') ?>
                                                        </a>
                                                    </li>
                                                    <?php endif; ?>
                                                    <?php if ($canEdit): ?>
                                                    <li><hr class="dropdown-divider"></li>
                                                    <li>
                                                        <a class="dropdown-item justify-content-start"
                                                           href="<?= $baseurl ?>/attributes/edit/<?= $attrId ?>"
                                                           onclick="event.preventDefault(); openModal('<?= $baseurl ?>/attributes/edit/<?= $attrId ?>');">
                                                            <i class="fas fa-pen-to-square me-2"></i>
                                                            <?= __('Edit') ?>
                                                        </a>
                                                    </li>
                                                    <li>
                                                        <a class="dropdown-item text-danger justify-content-start"
                                                           href="<?= $baseurl ?>/attributes/delete/<?= $attrId ?>"
                                                           onclick="event.preventDefault(); openModal('<?= $baseurl ?>/attributes/delete/<?= $attrId ?>', 'sm');">
                                                            <i class="fas fa-trash me-2"></i>
                                                            <?= __('Delete') ?>
                                                        </a>
                                                    </li>
                                                    <?php endif; ?>
                                                    <?= $this->element('AnalystData/add_controls', [
                                                        'objectType' => 'Attribute',
                                                        'objectUuid' => $attr['uuid'] ?? '',
                                                        'mode' => 'menu_items',
                                                    ]) ?>
                                                </ul>
                                            </div>
                                        </div>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                    <?php else: ?>
                        <p class="text-muted small fst-italic px-3 py-2 mb-0">
                            <i class="fas fa-info-circle me-1"></i>
                            <?= __('No visible attributes.') ?>
                        </p>
                    <?php endif; ?>

                </div>
            </div><!-- /.accordion-collapse -->

        </div><!-- /.accordion-item -->
        <?php endforeach; ?>
        </div><!-- /#objectAccordion -->

    <?php else: ?>
        <div class="card shadow-sm">
            <div class="card-body text-center text-muted py-5">
                <span class="misp-icon misp-icon-object misp-hexagone mb-3 opacity-25" style="font-size:2em;"></span>
                <p class="mb-0"><?= __('No objects in this event.') ?></p>
            </div>
        </div>
    <?php endif; ?>

    <!-- ── Bottom pagination ───────────────────────────────── -->
    <?php if ($totalPages > 1): ?>
    <div class="card shadow-sm mt-3">
        <div class="card-body py-2 d-flex justify-content-center">
            <nav aria-label="<?= __('Objects pagination') ?>">
                <ul class="pagination pagination-sm mb-0">
                    <?php if ($page > 1): ?>
                        <li class="page-item">
                            <a class="page-link obj-page-link"
                               href="#" data-page="<?= $page - 1 ?>">
                                <i class="fas fa-chevron-left"></i>
                            </a>
                        </li>
                    <?php endif; ?>

                    <?php for ($p = 1; $p <= $totalPages; $p++):
                        if (
                            $p === 1
                            || $p === $totalPages
                            || abs($p - $page) <= $window
                        ):
                    ?>
                        <li class="page-item <?= $p === $page ? 'active' : '' ?>">
                            <a class="page-link obj-page-link"
                               href="#" data-page="<?= $p ?>">
                                <?= $p ?>
                            </a>
                        </li>
                    <?php
                        elseif (abs($p - $page) === $window + 1):
                    ?>
                        <li class="page-item disabled">
                            <span class="page-link">&hellip;</span>
                        </li>
                    <?php endif; endfor; ?>

                    <?php if ($page < $totalPages): ?>
                        <li class="page-item">
                            <a class="page-link obj-page-link"
                               href="#" data-page="<?= $page + 1 ?>">
                                <i class="fas fa-chevron-right"></i>
                            </a>
                        </li>
                    <?php endif; ?>
                </ul>
            </nav>
        </div>
    </div>
    <?php endif; ?>

</div><!-- /#objectListContainer -->

<script>
(function () {
    var eventId      = <?= json_encode((string)$eventId) ?>;
    var errMsg       = <?= json_encode(__('Could not load objects.')) ?>;
    var _objBase     = baseurl + <?= json_encode($objectsUrl) ?>;
    var _deletedState = <?= (int)$currentDeleted ?>;
    var _proposalState = <?= (int)$currentProposal ?>;
    var _labelActive = <?= json_encode(__('Active filters')) ?>;
    var _labelClear  = <?= json_encode(__('Clear')) ?>;

    // Correct the baseIndexUrl set by filter_bar (it appended /index)
    baseIndexUrl = _objBase;

    function getContainer() {
        return document.querySelector('.ajax-tab-content[data-url*="viewObjects"]');
    }

    function buildObjectsUrl() {
        var url = _objBase;
        if (_deletedState) url += '/deleted:' + _deletedState;
        if (_proposalState) url += '/proposal:' + _proposalState;
        var cont  = getContainer();
        var field = cont ? cont.querySelector('#filterField') : null;
        if (field && field.value.trim()) {
            url += '/searchFor:' + encodeURIComponent(field.value.trim());
        }
        return url;
    }

    function loadObjects(url, searchTerm) {
        if (searchTerm === undefined) {
            var m = url.match(/searchFor:([^/]+)/);
            searchTerm = m ? decodeURIComponent(m[1]) : '';
        }
        var container = getContainer();
        if (!container) return;
        container.style.opacity       = '0.5';
        container.style.pointerEvents = 'none';
        fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) { return r.text(); })
            .then(function (html) {
                container.innerHTML       = html;
                container.style.opacity      = '';
                container.style.pointerEvents = '';
                container.querySelectorAll('script').forEach(function (oldScript) {
                    var newScript = document.createElement('script');
                    if (oldScript.src) {
                        newScript.src = oldScript.src;
                    } else {
                        newScript.textContent = oldScript.textContent;
                    }
                    document.head.appendChild(newScript);
                    document.head.removeChild(newScript);
                });
                // After scripts ran → #filterField has been cloned → restore value
                var field = container.querySelector('#filterField');
                if (field && searchTerm) field.value = searchTerm;
                updateActiveFilterBadge(
                    container,
                    searchTerm,
                    function () {
                        var clearUrl = _objBase;
                        if (_deletedState) clearUrl += '/deleted:' + _deletedState;
                        if (_proposalState) clearUrl += '/proposal:' + _proposalState;
                        loadObjects(clearUrl, '');
                    },
                    _labelActive,
                    _labelClear
                );
                container.scrollIntoView({ behavior: 'smooth', block: 'start' });
            })
            .catch(function () {
                container.style.opacity      = '';
                container.style.pointerEvents = '';
                showMessage('fail', errMsg);
            });
    }

    // Expose a reload API (mirrors window.mispView.attrs) so the edit-tag /
    // edit-galaxy modals can refresh this tab after saving.
    window.mispView = window.mispView || {};
    window.mispView.objects = Object.assign(window.mispView.objects || {}, {
        loadFn:  loadObjects,
        buildFn: buildObjectsUrl
    });

    // Clone #filterButton and #filterField to strip filter_bar.ctp's
    // window.location.href listeners (click on button + keypress Enter on field).
    var container = getContainer();

    var filterBtn = container ? container.querySelector('#filterButton') : null;
    if (filterBtn) {
        var newBtn = filterBtn.cloneNode(true);
        filterBtn.parentNode.replaceChild(newBtn, filterBtn);
        newBtn.addEventListener('click', function () { loadObjects(buildObjectsUrl()); });
    }

    var filterField = container ? container.querySelector('#filterField') : null;
    if (filterField) {
        var newField = filterField.cloneNode(true);
        filterField.parentNode.replaceChild(newField, filterField);
        newField.addEventListener('keypress', function (e) {
            if (e.key !== 'Enter') return;
            e.preventDefault();
            loadObjects(buildObjectsUrl());
        });
    }

    // Toggle buttons (deleted / proposals) — clone to strip default navigation,
    // flip the relevant state then reload from the full URL (which preserves the
    // other toggle + the search term).
    function wireObjToggle(selector, flip) {
        var btn = container ? container.querySelector(selector) : null;
        if (!btn) return;
        var fresh = btn.cloneNode(true);
        btn.parentNode.replaceChild(fresh, btn);
        fresh.addEventListener('click', function (e) {
            e.preventDefault();
            flip();
            loadObjects(buildObjectsUrl());
        });
    }
    wireObjToggle('.obj-deleted-toggle', function () { _deletedState = _deletedState ? 0 : 1; });
    wireObjToggle('.obj-proposal-toggle', function () { _proposalState = _proposalState ? 0 : 1; });

    // Pagination link clicks
    document.addEventListener('click', function (e) {
        var link = e.target.closest('.obj-page-link');
        if (!link) return;
        e.preventDefault();
        var p = link.dataset.page;
        if (!p) return;
        loadObjects(
            baseurl + <?= json_encode($objectsUrl) ?> + '/page:' + encodeURIComponent(p)
        );
    });
})();
</script>
