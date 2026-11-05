<?php
/**
 *
 * Read-only objects tab for a remote event preview.
 *
 */

$objects = array_values(array_filter(
    $data['objects'] ?? [],
    function ($previewObject) {
        return ($previewObject['objectType'] ?? '') === 'object';
    }
));

// Filtered here, as the Attributes tab is: the whole event is on hand.
App::uses('RemoteEventPreviewFilter', 'Tools');
$filters = RemoteEventPreviewFilter::active(
    $this->request->params['named'] ?? [],
    RemoteEventPreviewFilter::OBJECT_FILTERS
);
$panelChildren = RemoteEventPreviewFilter::children(
    array_merge(...array_column($objects, 'Attribute')),
    $objects,
    RemoteEventPreviewFilter::OBJECT_FILTERS
);
$hasObjects = !empty($objects);
$objects = RemoteEventPreviewFilter::objects($objects, $filters);
$tabUrl = $previewContext['objectsUrl'] ?? '';

$taggingEnabled = (bool)Configure::read('MISP.tagging');
$uid = 'preview-objects-' . h($data['Event']['id'] ?? $data['Event']['uuid'] ?? '0');


$distBadge = function ($dist) {
    // Remote data, so an out-of-range level is expected — get() falls back.
    $c = $this->DistributionLevel->get($dist);
    return sprintf(
        '<span class="badge d-inline-flex align-items-center px-2 py-1"'
        . ' style="background:%s;color:%s;border:1px solid %s;font-weight:500;">'
        . '<i class="%s"></i></span>',
        h($this->DistributionLevel->themed($c, 'bg')),
        h($this->DistributionLevel->themed($c, 'fg')),
        h($this->DistributionLevel->themed($c, 'border', '20')),
        h($c['icon'])
    );
};

$fmtSeen = function ($value) {
    $dt = date_create((string)$value);
    if ($dt === false) {
        return ['date' => (string)$value, 'time' => ''];
    }
    return ['date' => $dt->format('Y-m-d'), 'time' => $dt->format('H:i:s')];
};

$valueCell = function ($attr) {
    $dist = $this->element('genericElementsBS5/IndexTable/Fields/distribution', [
        'row' => $attr,
        'field' => ['data_path' => 'distribution', 'display' => 'short'],
    ]);
    $html = '<div class="d-flex flex-column gap-1">'
        . '<div class="d-flex align-items-baseline gap-2 mb-0 flex-wrap">'
        . $dist
        . '<p class="mb-0">' . h($attr['value'] ?? '') . '</p>'
        . '</div>';
    $html .= $this->element('genericElementsBS5/Badges/comment', ['comment' => $attr['comment'] ?? '']);
    return $html . '</div>';
};
?>

<div id="<?= $uid ?>-container" class="container-fluid px-0" data-ifp-scope="<?= h($tabUrl) ?>">

    <!-- ── Filter bar, as the scaffold draws it ──── -->
    <div class="ifp-card">
        <?= $this->element('genericElementsBS5/IndexTable/filter_bar', [
            'scaffold_data' => [
                // For the count beside the chips.
                'data' => $objects,
                'filter_bar' => [
                    'base_url' => $tabUrl,
                    'skip_pagination' => true,
                    // One list, no card view to switch to.
                    'view_switch' => false,
                    'chips' => ['labels' => ['name' => __('Template')]],
                    'children' => array_merge([
                        [
                            'type' => 'search',
                            'button' => __('Search'),
                            'placeholder' => __('Filter objects…'),
                            'mode' => 'legacy',
                            'name' => 'searchFor',
                        ],
                    ], $panelChildren),
                ],
            ],
            'item_url' => '/objects',
        ]) ?>
    </div>

    <?php if (empty($objects)): ?>
        <div class="card shadow-sm">
            <div class="card-body text-center text-muted py-5">
                <span class="misp-icon misp-icon-object misp-hexagone mb-3 opacity-25" style="font-size:2em;"></span>
                <p class="mb-0"><?= $hasObjects ? __('No object matches these filters.') : __('No objects in this event.') ?></p>
            </div>
        </div>
    <?php else: ?>
        <div class="accordion" id="<?= $uid ?>-accordion">
        <?php foreach ($objects as $idx => $object): ?>
            <?php
                $objId      = (int)($object['id'] ?? $idx);
                $collapseId = $uid . '-collapse-' . $objId;
                $headingId  = $uid . '-heading-' . $objId;
                $attrs      = $object['Attribute'] ?? [];
                $attrCount  = count($attrs);
            ?>
            <div class="accordion-item shadow-sm mb-2 rounded border preview-object-item">

                <h2 class="accordion-header" id="<?= $headingId ?>">
                    <button class="accordion-button collapsed py-2 px-3 rounded"
                            type="button"
                            data-bs-toggle="collapse"
                            data-bs-target="#<?= $collapseId ?>"
                            aria-expanded="false"
                            aria-controls="<?= $collapseId ?>">
                        <span class="d-flex align-items-center flex-wrap gap-2 w-100 me-2">
                            <?= $distBadge($object['distribution'] ?? 0) ?>
                            <span class="fw-semibold">
                                <span class="misp-icon misp-icon-object misp-hexagone me-1 text-secondary"></span>
                                <?= h($object['name'] ?? '') ?>
                            </span>
                            <?php if (!empty($object['meta-category'])): ?>
                                <span class="badge rounded-pill text-bg-light border text-secondary fw-normal">
                                    <?= h($object['meta-category']) ?>
                                </span>
                            <?php endif; ?>
                            <?= $this->element('genericElementsBS5/Badges/comment', ['comment' => $object['comment'] ?? '', 'inline' => true]) ?>
                            <span class="badge rounded-pill bg-secondary-subtle text-secondary ms-auto">
                                <?= __n('%s attribute', '%s attributes', $attrCount, $attrCount) ?>
                            </span>
                            <?php if (!empty($object['timestamp'])): ?>
                                <span class="text-muted small text-nowrap">
                                    <i class="fas fa-clock fa-xs me-1"></i><?= date('Y-m-d', (int)$object['timestamp']) ?>
                                </span>
                            <?php endif; ?>
                        </span>
                    </button>
                </h2>

                <div id="<?= $collapseId ?>" class="accordion-collapse collapse"
                     aria-labelledby="<?= $headingId ?>">
                    <div class="accordion-body p-0">

                        <!-- Object meta row (read-only) -->
                        <?php if (!empty($object['uuid']) || !empty($object['first_seen']) || !empty($object['last_seen']) || !empty($object['template_version'])): ?>
                        <div class="px-3 py-2 bg-light border-bottom d-flex flex-wrap align-items-center gap-3 small text-muted">
                            <?php if (!empty($object['uuid'])): ?>
                                <span class="d-inline-flex align-items-center gap-1">
                                    <i class="fas fa-fingerprint me-1"></i>
                                    <code class="user-select-all"><?= h($object['uuid']) ?></code>
                                    <button type="button" class="btn btn-sm btn-link p-0 text-muted lh-1"
                                            title="<?= h(__('Copy UUID')) ?>"
                                            onclick="copyValueToClipboard('<?= h($object['uuid']) ?>', '<?= h(__('UUID copied to clipboard')) ?>');">
                                        <i class="fas fa-copy"></i>
                                    </button>
                                </span>
                            <?php endif; ?>
                            <?php if (!empty($object['first_seen'])): $fs = $fmtSeen($object['first_seen']); ?>
                                <span class="d-inline-flex align-items-center gap-1" title="<?= h($object['first_seen']) ?>">
                                    <i class="fas fa-calendar-plus text-secondary"></i>
                                    <span class="text-uppercase fw-semibold" style="font-size:.65rem;letter-spacing:.04em;"><?= __('First seen') ?></span>
                                    <span class="badge bg-white border text-secondary fw-normal font-monospace">
                                        <?= h($fs['date']) ?><?php if ($fs['time'] !== ''): ?><span class="text-muted ms-1"><?= h($fs['time']) ?></span><?php endif; ?>
                                    </span>
                                </span>
                            <?php endif; ?>
                            <?php if (!empty($object['last_seen'])): $ls = $fmtSeen($object['last_seen']); ?>
                                <span class="d-inline-flex align-items-center gap-1" title="<?= h($object['last_seen']) ?>">
                                    <i class="fas fa-calendar-check text-secondary"></i>
                                    <span class="text-uppercase fw-semibold" style="font-size:.65rem;letter-spacing:.04em;"><?= __('Last seen') ?></span>
                                    <span class="badge bg-white border text-secondary fw-normal font-monospace">
                                        <?= h($ls['date']) ?><?php if ($ls['time'] !== ''): ?><span class="text-muted ms-1"><?= h($ls['time']) ?></span><?php endif; ?>
                                    </span>
                                </span>
                            <?php endif; ?>
                            <?php if (!empty($object['template_version'])): ?>
                                <span>
                                    <span class="misp-icon misp-icon-tag misp-hexagone me-1"></span>
                                    <?= __('Template v%s', h($object['template_version'])) ?>
                                </span>
                            <?php endif; ?>
                        </div>
                        <?php endif; ?>

                        <!-- Attribute table (read-only) -->
                        <?php if (!empty($attrs)): ?>
                        <div class="table-responsive">
                            <table class="table table-sm table-hover align-middle mb-0">
                                <thead class="table-light">
                                    <tr>
                                        <th style="width:30%"><?= __('Value') ?></th>
                                        <th style="width:10%"><?= __('Category') ?></th>
                                        <th style="width:10%"><?= __('Type') ?></th>
                                        <?php if ($taggingEnabled): ?><th style="width:15%"><?= __('Tags') ?></th><?php endif; ?>
                                        <th style="width:15%"><?= __('Galaxies') ?></th>
                                        <th class="text-center"><?= __('IDS') ?></th>
                                        <th class="text-center"><?= __('Correlate') ?></th>
                                        <th><?= __('Related Events') ?></th>
                                        <th><?= __('Feed Hits') ?></th>
                                        <th><?= __('Sightings') ?></th>
                                    </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($attrs as $attr): ?>
                                    <tr>
                                        <td class="text-break"><?= $valueCell($attr) ?></td>
                                        <td>
                                            <div class="d-flex align-items-center gap-1">
                                                <?= $this->element('genericElementsBS5/Badges/category', ['category' => $attr['category'] ?? '']) ?>
                                                <?= $this->element('genericElementsBS5/Badges/object_relation', ['relation' => $attr['object_relation'] ?? '']) ?>
                                            </div>
                                        </td>
                                        <td><?= $this->element('genericElementsBS5/Badges/type', ['type' => $attr['type'] ?? '']) ?></td>
                                        <?php if ($taggingEnabled): ?>
                                        <td><?= $this->element('genericElementsBS5/IndexTable/Fields/tag_list', ['row' => $attr, 'field' => ['data_path' => 'Tag']]) ?></td>
                                        <?php endif; ?>
                                        <td><?= $this->element('genericElementsBS5/IndexTable/Fields/galaxy', ['row' => $attr, 'field' => ['data_path' => 'Galaxy'], 'data_path' => 'Galaxy']) ?></td>
                                        <td class="text-center">
                                            <?php $toIds = !empty($attr['to_ids']); ?>
                                            <i class="fas fa-shield-halved <?= $toIds ? 'text-warning' : 'text-secondary' ?>"
                                               style="font-size:1.2em;"
                                               title="<?= $toIds ? __('IDS active') : __('IDS inactive') ?>"></i>
                                        </td>
                                        <td class="text-center">
                                            <?php $corrOff = !empty($attr['disable_correlation']); ?>
                                            <i class="fas <?= $corrOff ? 'fa-link-slash text-secondary' : 'fa-link text-success' ?>"
                                               style="font-size:1.2em;"
                                               title="<?= $corrOff ? __('Correlation disabled') : __('Correlation enabled') ?>"></i>
                                        </td>
                                        <td><?= $this->element('genericElementsBS5/IndexTable/Fields/relatedEvents', ['row' => $attr, 'field' => []]) ?></td>
                                        <td><?= $this->element('genericElementsBS5/IndexTable/Fields/feedHits', ['row' => ['Attribute' => $attr], 'field' => []]) ?></td>
                                        <td><?= $this->element('genericElementsBS5/IndexTable/Fields/sightings', ['row' => $attr, 'field' => ['sightings' => ['data' => [], 'csv' => []]]]) ?></td>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                        <?php else: ?>
                            <p class="text-muted small fst-italic px-3 py-2 mb-0">
                                <i class="fas fa-info-circle me-1"></i><?= __('No visible attributes.') ?>
                            </p>
                        <?php endif; ?>

                    </div>
                </div>
            </div>
        <?php endforeach; ?>
        </div>
    <?php endif; ?>

</div>
