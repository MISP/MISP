<?php
$eventId = (int)$event['Event']['id'];
$typesWithData = ['attachment', 'malware-sample'];

// Id of the enriched attribute/object (NOT the event)
$sourceId = isset($sourceId) ? $sourceId : $eventId;
$backModel = isset($model) ? $model : 'Attribute';
$backType = isset($type) ? $type : 'Enrichment';

$attributesCount = isset($event['Attribute']) ? count($event['Attribute']) : 0;
$objectsCount    = isset($event['Object']) ? count($event['Object']) : 0;
$reportsCount    = isset($event['EventReport']) ? count($event['EventReport']) : 0;
if (!empty($event['Object'])) {
    foreach ($event['Object'] as $o) {
        if (!empty($o['Attribute'])) {
            $attributesCount += count($o['Attribute']);
        }
    }
}

// Distribution colour map, also handed to JS further down via json_encode.
$distMeta = $this->DistributionLevel->all();

$distPicker = function ($scope, $selected) use ($distributions, $sgs) {
    $selected = ($selected === null || $selected === '') ? array_key_first($distributions) : (int)$selected;
    if (!isset($distributions[$selected])) {
        $selected = (int)array_key_first($distributions);
    }
    ob_start(); ?>
    <span class="om-dist-picker position-relative d-inline-flex align-items-center" style="cursor:pointer;" title="<?= __('Change distribution') ?>">
        <span class="om-dist-face"><?= $this->element('genericElementsBS5/Badges/distribution', ['distribution' => $selected, 'full' => false]) ?></span>
        <select class="om-dist-native <?= h($scope) ?>-dist position-absolute top-0 start-0 w-100 h-100 opacity-0 border-0 p-0 m-0"
                style="cursor:pointer;" aria-label="<?= __('Distribution') ?>">
            <?php foreach ($distributions as $dKey => $dVal): ?>
                <option value="<?= h($dKey) ?>"<?= $dKey == $selected ? ' selected' : '' ?>><?= h($dVal) ?></option>
            <?php endforeach; ?>
        </select>
    </span>
    <select class="<?= h($scope) ?>-sg form-select form-select-sm mt-1" style="<?= $selected == 4 ? '' : 'display:none;' ?>">
        <?php foreach ($sgs as $sgKey => $sgVal): ?>
            <option value="<?= h($sgKey) ?>"><?= h($sgVal) ?></option>
        <?php endforeach; ?>
    </select>
    <?php
    return ob_get_clean();
};

// Client-only IDS shield
$idsToggle = function ($on) {
    ob_start(); ?>
    <span role="button" class="om-ids" data-on="<?= $on ? '1' : '0' ?>"
          title="<?= $on ? __('IDS active — click to disable') : __('IDS inactive — click to enable') ?>"
          aria-label="<?= __('Toggle IDS flag') ?>">
        <i class="fas fa-shield-halved <?= $on ? 'text-warning' : 'text-secondary' ?>" style="font-size:1.2em;"></i>
    </span>
    <?php
    return ob_get_clean();
};

// Client-only correlation link
$corrToggle = function ($disabled) {
    ob_start(); ?>
    <span role="button" class="om-corr" data-off="<?= $disabled ? '1' : '0' ?>"
          title="<?= $disabled ? __('Correlation disabled — click to enable') : __('Correlation enabled — click to disable') ?>"
          aria-label="<?= __('Toggle correlation') ?>">
        <i class="fas <?= $disabled ? 'fa-link-slash text-secondary' : 'fa-link text-success' ?>" style="font-size:1.2em;"></i>
    </span>
    <?php
    return ob_get_clean();
};

// Tags -> JSON [{name, colour, local}] carried on a data attribute (read-only).
$tagsJson = function ($tags) {
    $list = [];
    if (!empty($tags)) {
        foreach ($tags as $tag) {
            $list[] = [
                'name'   => $tag['name'],
                'colour' => !empty($tag['colour']) ? $tag['colour'] : '#0088cc',
                'local'  => !empty($tag['local']) ? 1 : 0,
            ];
        }
    }
    return h(json_encode($list));
};

// Small inline tag chips for display
$tagChips = function ($tags) {
    if (empty($tags)) {
        return '';
    }
    $out = '<span class="d-inline-flex flex-wrap gap-1 ms-1 align-middle">';
    foreach ($tags as $tag) {
        $colour = !empty($tag['colour']) ? $tag['colour'] : '#0088cc';
        $text = explode('=', $tag['name']);
        $text = trim(end($text), '"');
        $out .= '<span class="badge" style="background-color:' . h($colour) . ';font-size:.65rem;" title="' . h($tag['name']) . '">' . h($text) . '</span>';
    }
    $out .= '</span>';
    return $out;
};

$valueDisplay = function ($attribute) {
    if (($attribute['type'] ?? '') === 'link') {
        return '<a href="' . h($attribute['value']) . '" rel="noreferrer noopener" target="_blank">' . h($attribute['value']) . '</a>';
    }
    return h($attribute['value']);
};

// Reusable per-attribute cells (shared by object attributes and standalone ones).
$attrTableHead = function () use ($idsToggle) {
    ob_start(); ?>
    <thead class="table-light">
        <tr class="small text-muted">
            <th style="width:1%"></th>
            <th><?= __('Distribution') ?></th>
            <th><?= __('Category') ?></th>
            <th><?= __('Type') ?></th>
            <th><?= __('Value') ?></th>
            <th class="text-center"><?= __('IDS') ?></th>
            <th class="text-center"><?= __('Correlate') ?></th>
            <th><?= __('Comment') ?></th>
        </tr>
    </thead>
    <?php
    return ob_get_clean();
};
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(72,67,92,.06);
            border-bottom:2px solid var(--enrichment);">
    <div>
        <div class="text-enrichment text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= h($type === 'Cortex' ? __('Cortex') : __('Enrichment')) ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-wand-magic-sparkles text-enrichment" style="font-size:1.2rem;"></i>
            <?= __('Enrichment results') ?>
        </h4>
        <div class="text-muted small mt-1">
            <?= __('Event') ?>: <strong class="text-body">#<?= h($eventId) ?></strong>
        </div>
    </div>
    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="<?= __('Close') ?>"></button>
</div>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4 pb-3" id="omResolveRoot" style="background:var(--bs-tertiary-bg, #f8f9fa);">
<?php if (empty($event['Attribute']) && empty($event['Object']) && empty($event['EventReport'])): ?>
    <div class="alert alert-light border mb-0 d-flex align-items-center gap-2">
        <i class="fas fa-circle-info text-muted"></i>
        <?= __('The module returned no attributes, objects or reports for this data.') ?>
    </div>
<?php else: ?>

    <?php
    echo $this->Form->create('Event', [
        'url' => $baseurl . '/events/handleModuleResults/' . $eventId,
        'id'  => 'resolvedMispForm',
    ]);
    echo $this->Form->input('data', ['type' => 'hidden', 'value' => json_encode($event)]);
    echo $this->Form->input('JsonObject', ['type' => 'text', 'label' => false, 'div' => false, 'id' => 'ResolvedJsonObject', 'value' => '', 'style' => 'display:none;']);
    echo $this->Form->input('default_comment', ['type' => 'text', 'label' => false, 'div' => false, 'value' => $importComment, 'style' => 'display:none;']);
    echo $this->Form->end();
    ?>

    <!-- event-level tags carried for the payload (read-only) -->
    <span id="omEventTags" class="d-none" data-tags="<?= $tagsJson($event['Tag'] ?? []) ?>"></span>

    <div class="d-flex flex-wrap align-items-center gap-3 mb-2 small text-muted">
        <span><i class="misp-icon misp-icon-object misp-hexagone me-1"></i><span class="om-count-objects"><?= $objectsCount ?></span> <?= __('object(s)') ?></span>
        <span><i class="misp-icon misp-icon-attribute misp-hexagone me-1"></i><span class="om-count-attributes"><?= $attributesCount ?></span> <?= __('attribute(s)') ?></span>
        <span><i class="fas fa-file-lines me-1"></i><span class="om-count-reports"><?= $reportsCount ?></span> <?= __('report(s)') ?></span>
        <?php if ($objectsCount > 1): ?>
            <span class="ms-auto d-flex gap-2">
                <button type="button" class="btn btn-link btn-sm p-0 text-decoration-none" id="omExpandAll"><i class="fas fa-angles-down me-1"></i><?= __('Expand all') ?></button>
                <button type="button" class="btn btn-link btn-sm p-0 text-decoration-none" id="omCollapseAll"><i class="fas fa-angles-up me-1"></i><?= __('Collapse all') ?></button>
            </span>
        <?php endif; ?>
    </div>

    <!-- ── SCROLL WINDOW ────────────────────────────────────── -->
    <div id="omResolveScroll" class="pe-1" style="max-height:60vh; overflow-y:auto;">

    <?php if (!empty($event['EventReport'])): ?>
    <!-- ── EVENT REPORTS ────────────────────────────────────── -->
    <div class="text-event text-uppercase fw-semibold mb-2" style="font-size:.6rem; letter-spacing:.1em;"><?= __('Reports') ?></div>
    <?php foreach ($event['EventReport'] as $report): ?>
        <div class="card border-0 shadow-sm mb-2 om-report"
             data-name="<?= h($report['name']) ?>"
             data-uuid="<?= h($report['uuid']) ?>">
            <div class="card-body py-2">
                <div class="d-flex align-items-start gap-2">
                    <div class="flex-grow-1">
                        <div class="fw-semibold"><i class="fas fa-file-lines text-muted me-1"></i><?= h($report['name']) ?></div>
                        <div class="text-muted small text-truncate" style="max-width:100%;"><?= h($report['content']) ?></div>
                        <textarea class="d-none om-report-content"><?= h($report['content']) ?></textarea>
                    </div>
                    <div><?= $distPicker('om-report', $report['distribution'] ?? null) ?></div>
                    <button type="button" class="btn btn-sm btn-light text-danger om-remove" title="<?= __('Remove from import') ?>">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
    <?php endif; ?>

    <?php if (!empty($event['Object'])): ?>
    <!-- ── OBJECTS (collapsed accordion) ────────────────────── -->
    <div class="text-event text-uppercase fw-semibold mt-3 mb-2" style="font-size:.6rem; letter-spacing:.1em;"><?= __('Objects') ?></div>
    <div class="accordion" id="omObjAccordion">
    <?php foreach ($event['Object'] as $o => $object): ?>
        <?php
        $references = [];
        if (!empty($object['ObjectReference'])) {
            foreach ($object['ObjectReference'] as $ref) {
                $references[] = [
                    'referenced_uuid'   => $ref['referenced_uuid'],
                    'relationship_type' => $ref['relationship_type'],
                ];
            }
        }
        $oaCount = count($object['Attribute'] ?? []);
        $bodyId  = 'omObjBody_' . $o;
        ?>
        <div class="accordion-item border-0 shadow-sm mb-2 rounded om-object"
             data-uuid="<?= h($object['uuid']) ?>"
             data-name="<?= h($object['name']) ?>"
             data-meta-category="<?= h($object['meta-category'] ?? '') ?>"
             data-id="<?= h($object['id'] ?? '') ?>"
             data-description="<?= h($object['description'] ?? '') ?>"
             data-template-uuid="<?= h($object['template_uuid'] ?? '') ?>"
             data-template-version="<?= h($object['template_version'] ?? '') ?>"
             data-references="<?= h(json_encode($references)) ?>">
            <h2 class="accordion-header">
                <button class="accordion-button collapsed py-2 px-3 rounded shadow-none" type="button"
                        data-bs-toggle="collapse" data-bs-target="#<?= $bodyId ?>"
                        aria-expanded="false" aria-controls="<?= $bodyId ?>">
                    <span class="d-flex align-items-center flex-wrap gap-2 w-100 me-2">
                        <span class="fw-semibold">
                            <span class="misp-icon misp-icon-object misp-hexagone me-1 text-secondary"></span>
                            <?= h($object['name']) ?>
                        </span>
                        <?php if (!empty($object['meta-category'])): ?>
                            <span class="badge rounded-pill text-bg-light border text-secondary fw-normal"><?= h($object['meta-category']) ?></span>
                        <?php endif; ?>
                        <?php if (!empty($references)): ?>
                            <span class="text-muted small"><i class="fas fa-diagram-project me-1"></i><?= count($references) ?></span>
                        <?php endif; ?>
                        <span class="text-muted small fst-italic mt-1"><?= h($object['uuid']) ?></span>
                        <span class="badge rounded-pill bg-secondary-subtle text-secondary ms-auto">
                            <?= __n('%s attribute', '%s attributes', $oaCount, $oaCount) ?>
                        </span>
                        <span class="om-remove text-danger d-inline-flex align-items-center px-1" title="<?= __('Remove this object from import') ?>" style="cursor:pointer;">
                            <i class="fas fa-trash"></i>
                        </span>
                    </span>
                </button>
            </h2>
            <div id="<?= $bodyId ?>" class="accordion-collapse collapse">
                <div class="accordion-body pt-2">
                    <div class="row g-2 mb-2 align-items-start">
                        <div class="col-md-6">
                            <label class="form-label small text-muted mb-1"><?= __('Comment') ?></label>
                            <textarea class="form-control form-control-sm om-object-comment" rows="1"
                                      placeholder="<?= h($importComment) ?>"><?= !empty($object['comment']) ? h($object['comment']) : '' ?></textarea>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label small text-muted mb-1 d-block"><?= __('Distribution') ?></label>
                            <?= $distPicker('om-object', $object['distribution'] ?? null) ?>
                        </div>
                        <div class="col-md-3">
                            <label class="form-label small text-muted mb-1 d-block"><?= __('Seen (first / last)') ?></label>
                            <input type="text" class="form-control form-control-sm om-object-fs mb-1" placeholder="<?= __('First seen') ?>" value="<?= h($object['first_seen'] ?? '') ?>">
                            <input type="text" class="form-control form-control-sm om-object-ls" placeholder="<?= __('Last seen') ?>" value="<?= h($object['last_seen'] ?? '') ?>">
                        </div>
                    </div>

                    <?php if (!empty($object['Attribute'])): ?>
                    <div class="table-responsive">
                    <table class="table table-sm table-hover align-middle mb-0">
                        <?= $attrTableHead() ?>
                        <tbody>
                        <?php foreach ($object['Attribute'] as $oa): ?>
                            <tr class="om-object-attr"
                                data-object-relation="<?= h($oa['object_relation'] ?? '') ?>"
                                data-category="<?= h($oa['category'] ?? '') ?>"
                                data-type="<?= h($oa['type'] ?? '') ?>"
                                data-value="<?= h($oa['value'] ?? '') ?>"
                                data-uuid="<?= h($oa['uuid'] ?? '') ?>"
                                data-fs="<?= h($oa['first_seen'] ?? '') ?>"
                                data-ls="<?= h($oa['last_seen'] ?? '') ?>"
                                data-tags="<?= $tagsJson($oa['Tag'] ?? []) ?>"
                                <?php if (in_array($oa['type'] ?? '', $typesWithData, true)): ?>
                                    data-attach="<?= h($oa['data'] ?? '') ?>"
                                    data-encrypt="<?= h($oa['encrypt'] ?? '') ?>"
                                <?php endif; ?>>
                                <td><button type="button" class="btn btn-sm btn-light text-danger p-1 om-remove" title="<?= __('Remove from import') ?>"><i class="fas fa-trash"></i></button></td>
                                <td><?= $distPicker('om-oa', $oa['distribution'] ?? null) ?></td>
                                <td>
                                    <div class="d-flex align-items-center gap-1">
                                        <?= $this->element('genericElementsBS5/Badges/category', ['category' => $oa['category'] ?? '', 'full' => false]) ?>
                                        <?php if (!empty($oa['object_relation'])): ?>
                                            <span class="badge bg-dark text-white fw-normal"><?= h($oa['object_relation']) ?></span>
                                        <?php endif; ?>
                                    </div>
                                </td>
                                <td><?= $this->element('genericElementsBS5/Badges/type', ['type' => $oa['type'] ?? '']) ?></td>
                                <td class="font-monospace small text-break"><?= $valueDisplay($oa) ?><?= $tagChips($oa['Tag'] ?? []) ?></td>
                                <td class="text-center"><?= $idsToggle(!empty($oa['to_ids'])) ?></td>
                                <td class="text-center"><?= $corrToggle(!empty($oa['disable_correlation'])) ?></td>
                                <td><input type="text" class="form-control form-control-sm om-oa-comment" value="<?= !empty($oa['comment']) ? h($oa['comment']) : '' ?>"></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <?php if (!empty($event['Attribute'])): ?>
    <!-- ── ATTRIBUTES ───────────────────────────────────────── -->
    <div class="text-event text-uppercase fw-semibold mt-3 mb-2" style="font-size:.6rem; letter-spacing:.1em;"><?= __('Attributes') ?></div>
    <div class="card border-0 shadow-sm">
        <div class="card-body p-0">
            <div class="table-responsive">
            <table class="table table-sm table-hover align-middle mb-0">
                <?= $attrTableHead() ?>
                <tbody>
                <?php foreach ($event['Attribute'] as $attribute): ?>
                    <?php $catIsArray = isset($attribute['category']) && is_array($attribute['category']); $typeIsArray = isset($attribute['type']) && is_array($attribute['type']); ?>
                    <tr class="om-attr"
                        data-value="<?= h($attribute['value'] ?? '') ?>"
                        data-uuid="<?= h($attribute['uuid'] ?? '') ?>"
                        data-fs="<?= h($attribute['first_seen'] ?? '') ?>"
                        data-ls="<?= h($attribute['last_seen'] ?? '') ?>"
                        data-tags="<?= $tagsJson($attribute['Tag'] ?? []) ?>"
                        <?php if (!$catIsArray): ?>data-category="<?= h($attribute['category'] ?? '') ?>"<?php endif; ?>
                        <?php if (!$typeIsArray): ?>data-type="<?= h($attribute['type'] ?? '') ?>"<?php endif; ?>
                        <?php if (!$typeIsArray && in_array($attribute['type'] ?? '', $typesWithData, true)): ?>
                            data-attach="<?= h($attribute['data'] ?? '') ?>"
                            data-encrypt="<?= h($attribute['encrypt'] ?? '') ?>"
                        <?php endif; ?>>
                        <td class="ps-3"><button type="button" class="btn btn-sm btn-light text-danger p-1 om-remove" title="<?= __('Remove from import') ?>"><i class="fas fa-trash"></i></button></td>
                        <td class="pe-3"><?= $distPicker('om-attr', $attribute['distribution'] ?? null) ?></td>
                        <td>
                            <?php if ($catIsArray): ?>
                                <select class="form-select form-select-sm om-attr-cat-select">
                                    <?php foreach ($attribute['category'] as $c): ?><option><?= h($c) ?></option><?php endforeach; ?>
                                </select>
                            <?php else: ?>
                                <?= $this->element('genericElementsBS5/Badges/category', ['category' => $attribute['category'] ?? '', 'full' => false]) ?>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($typeIsArray): ?>
                                <select class="form-select form-select-sm om-attr-type-select">
                                    <?php foreach ($attribute['type'] as $t): ?><option><?= h($t) ?></option><?php endforeach; ?>
                                </select>
                            <?php else: ?>
                                <?= $this->element('genericElementsBS5/Badges/type', ['type' => $attribute['type'] ?? '']) ?>
                            <?php endif; ?>
                        </td>
                        <td class="font-monospace small text-break"><?= $valueDisplay($attribute) ?><?= $tagChips($attribute['Tag'] ?? []) ?></td>
                        <td class="text-center"><?= $idsToggle(!empty($attribute['to_ids'])) ?></td>
                        <td class="text-center"><?= $corrToggle(!empty($attribute['disable_correlation'])) ?></td>
                        <td><input type="text" class="form-control form-control-sm om-attr-comment" placeholder="<?= h($importComment) ?>" value="<?= !empty($attribute['comment']) ? h($attribute['comment']) : '' ?>"></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
            </div>
        </div>
    </div>
    <?php endif; ?>

    </div>

    <!-- ── FOOTER ───────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center mt-3 pt-3 flex-wrap gap-2"
         style="border-top:1px solid var(--bs-border-color, #dee2e6);">
        <div class="text-muted" style="font-size:.75rem;">
            <?= __('Review and remove anything you don\'t want, then import into event') ?> #<?= h($eventId) ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    onclick="openModal('<?= $baseurl ?>/events/queryEnrichment/<?= h($sourceId) ?>/0/<?= h($backType) ?>/<?= h($backModel) ?>');">
                <i class="fas fa-arrow-left me-1"></i><?= __('Back') ?>
            </button>
            <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <button type="button" class="btn btn-event btn-sm text-white" id="omResolveSubmit">
                <i class="fas fa-circle-plus me-1"></i><?= __('Import') ?>
            </button>
        </div>
    </div>
<?php endif; ?>
</div>

<script>
(function () {
    var EVENT_ID = <?= $eventId ?>;
    var form = document.getElementById('resolvedMispForm');
    var root = document.getElementById('omResolveRoot');
    if (!form || !root) { return; }

    form.addEventListener('submit', function (e) { e.preventDefault(); });

    // JSON_FORCE_OBJECT keeps this a keyed object: the levels are contiguous
    // from 0, so json_encode would otherwise emit an array.
    var distMeta = <?= json_encode($distMeta, JSON_FORCE_OBJECT) ?>;
    var distFallback = { bg: '#f1f1f1', color: '#333', icon: 'fas fa-question', label: '?' };

    // Rebuild the coloured index badge
    function distBadgeHtml(level, full) {
        var m = distMeta[level] || distFallback;
        return '<span class="badge d-inline-flex align-items-center px-2 py-1" '
             + 'style="background-color:' + m.bg + ';color:' + m.color + ';border:1px solid ' + m.color + '20;font-weight:500;" '
             + 'title="' + m.label + '"><i class="' + m.icon + '"></i>'
             + (full ? '<span class="ms-1">' + m.label + '</span>' : '') + '</span>';
    }

    // Refresh the object/attribute/report counters from what is still kept.
    function recount() {
        var objects = 0, attributes = 0, reports = 0;
        root.querySelectorAll('.om-object').forEach(function (o) {
            if (o.dataset.removed === '1') { return; }
            objects++;
            o.querySelectorAll('.om-object-attr').forEach(function (r) {
                if (r.dataset.removed !== '1') { attributes++; }
            });
        });
        root.querySelectorAll('.om-attr').forEach(function (r) {
            if (r.dataset.removed !== '1') { attributes++; }
        });
        root.querySelectorAll('.om-report').forEach(function (r) {
            if (r.dataset.removed !== '1') { reports++; }
        });
        var set = function (sel, n) { var el = root.querySelector(sel); if (el) { el.textContent = n; } };
        set('.om-count-objects', objects);
        set('.om-count-attributes', attributes);
        set('.om-count-reports', reports);
    }

    // ── Click interactions (remove / IDS / correlation toggles) ────────
    root.addEventListener('click', function (e) {
        var rm = e.target.closest('.om-remove');
        if (rm) {
            e.preventDefault();
            e.stopPropagation();
            var item = rm.closest('.om-object-attr, .om-attr, .om-report, .om-object');
            if (item) {
                item.dataset.removed = '1';
                item.style.display = 'none';
                recount();
            }
            return;
        }
        var ids = e.target.closest('.om-ids');
        if (ids) {
            var on = ids.dataset.on !== '1';
            ids.dataset.on = on ? '1' : '0';
            var i = ids.querySelector('i');
            i.classList.toggle('text-warning', on);
            i.classList.toggle('text-secondary', !on);
            return;
        }
        var corr = e.target.closest('.om-corr');
        if (corr) {
            var off = corr.dataset.off !== '1';
            corr.dataset.off = off ? '1' : '0';
            var ic = corr.querySelector('i');
            ic.classList.toggle('fa-link', !off);
            ic.classList.toggle('text-success', !off);
            ic.classList.toggle('fa-link-slash', off);
            ic.classList.toggle('text-secondary', off);
        }
    });

    // ── Distribution: repaint the face badge + reveal sharing group on lvl 4 ──
    root.addEventListener('change', function (e) {
        var sel = e.target.closest('.om-dist-native');
        if (!sel) { return; }
        var picker = sel.closest('.om-dist-picker');
        var face = picker ? picker.querySelector('.om-dist-face') : null;
        if (face) { face.innerHTML = distBadgeHtml(sel.value, false); }
        // The sharing-group select is the picker's next sibling.
        var sg = picker ? picker.nextElementSibling : null;
        if (sg && sg.tagName === 'SELECT') {
            sg.style.display = (sel.value === '4') ? '' : 'none';
        }
    });

    // ── Expand / collapse all objects ─────────────────────────
    var accordion = document.getElementById('omObjAccordion');
    function setAll(show) {
        if (!accordion || typeof bootstrap === 'undefined') { return; }
        accordion.querySelectorAll('.accordion-collapse').forEach(function (c) {
            var inst = bootstrap.Collapse.getOrCreateInstance(c, { toggle: false });
            show ? inst.show() : inst.hide();
        });
    }
    var expandAll = document.getElementById('omExpandAll');
    var collapseAll = document.getElementById('omCollapseAll');
    if (expandAll) { expandAll.addEventListener('click', function () { setAll(true); }); }
    if (collapseAll) { collapseAll.addEventListener('click', function () { setAll(false); }); }

    // ── Payload collection ────────────────────────────────────
    function parseTags(el) {
        try { return JSON.parse(el.getAttribute('data-tags') || '[]'); }
        catch (e) { return []; }
    }
    function dist(scope, el) {
        var d = el.querySelector('.' + scope + '-dist');
        var s = el.querySelector('.' + scope + '-sg');
        var v = d ? d.value : '0';
        return { distribution: v, sharing_group_id: (v === '4' && s) ? s.value : '0' };
    }

    var submitBtn = document.getElementById('omResolveSubmit');
    submitBtn.addEventListener('click', function () {
        var collected = {};

        // Event-level tags.
        var tagsEl = document.getElementById('omEventTags');
        if (tagsEl) {
            var evTags = parseTags(tagsEl);
            if (evTags.length) {
                collected.Tag = evTags.map(function (t) { return { name: t.name }; });
            }
        }

        // Objects (+ nested object attributes).
        var objects = [];
        root.querySelectorAll('.om-object').forEach(function (objEl) {
            if (objEl.dataset.removed === '1') { return; }
            var d = dist('om-object', objEl);
            var references = [];
            try { references = JSON.parse(objEl.getAttribute('data-references') || '[]'); }
            catch (e) { references = []; }
            var obj = {
                uuid: objEl.getAttribute('data-uuid'),
                import_object: true,
                name: objEl.getAttribute('data-name'),
                meta_category: objEl.getAttribute('data-meta-category'),
                distribution: d.distribution,
                sharing_group_id: d.sharing_group_id,
                comment: objEl.querySelector('.om-object-comment').value,
                first_seen: objEl.querySelector('.om-object-fs').value,
                last_seen: objEl.querySelector('.om-object-ls').value
            };
            if (objEl.getAttribute('data-id')) { obj.id = objEl.getAttribute('data-id'); }
            if (objEl.getAttribute('data-description')) { obj.description = objEl.getAttribute('data-description'); }
            if (objEl.getAttribute('data-template-uuid')) { obj.template_uuid = objEl.getAttribute('data-template-uuid'); }
            if (objEl.getAttribute('data-template-version')) { obj.template_version = objEl.getAttribute('data-template-version'); }
            if (references.length) {
                obj.ObjectReference = references.map(function (r) {
                    return {
                        object_uuid: obj.uuid,
                        referenced_uuid: r.referenced_uuid,
                        relationship_type: r.relationship_type
                    };
                });
            }
            var objAttrs = [];
            objEl.querySelectorAll('.om-object-attr').forEach(function (row) {
                if (row.dataset.removed === '1') { return; }
                var od = dist('om-oa', row);
                var a = {
                    import_attribute: true,
                    object_relation: row.getAttribute('data-object-relation'),
                    category: row.getAttribute('data-category'),
                    type: row.getAttribute('data-type'),
                    value: row.getAttribute('data-value'),
                    uuid: row.getAttribute('data-uuid'),
                    to_ids: row.querySelector('.om-ids').dataset.on === '1',
                    disable_correlation: row.querySelector('.om-corr').dataset.off === '1',
                    comment: row.querySelector('.om-oa-comment').value,
                    distribution: od.distribution,
                    sharing_group_id: od.sharing_group_id,
                    first_seen: row.getAttribute('data-fs') || '',
                    last_seen: row.getAttribute('data-ls') || ''
                };
                var oaTags = parseTags(row);
                if (oaTags.length) { a.Tag = oaTags; }
                if (row.hasAttribute('data-attach') && row.getAttribute('data-attach')) { a.data = row.getAttribute('data-attach'); }
                if (row.hasAttribute('data-encrypt') && row.getAttribute('data-encrypt')) { a.encrypt = row.getAttribute('data-encrypt'); }
                objAttrs.push(a);
            });
            if (objAttrs.length) { obj.Attribute = objAttrs; }
            objects.push(obj);
        });
        if (objects.length) { collected.Object = objects; }

        // Standalone attributes.
        var attributes = [];
        root.querySelectorAll('.om-attr').forEach(function (row) {
            if (row.dataset.removed === '1') { return; }
            var ad = dist('om-attr', row);
            var catSel = row.querySelector('.om-attr-cat-select');
            var typeSel = row.querySelector('.om-attr-type-select');
            var a = {
                import_attribute: true,
                category: catSel ? catSel.value : row.getAttribute('data-category'),
                type: typeSel ? typeSel.value : row.getAttribute('data-type'),
                value: row.getAttribute('data-value'),
                uuid: row.getAttribute('data-uuid'),
                to_ids: row.querySelector('.om-ids').dataset.on === '1',
                disable_correlation: row.querySelector('.om-corr').dataset.off === '1',
                comment: row.querySelector('.om-attr-comment').value,
                distribution: ad.distribution,
                sharing_group_id: ad.sharing_group_id,
                first_seen: row.getAttribute('data-fs') || '',
                last_seen: row.getAttribute('data-ls') || ''
            };
            var aTags = parseTags(row);
            if (aTags.length) { a.Tag = aTags; }
            if (row.hasAttribute('data-attach') && row.getAttribute('data-attach')) { a.data = row.getAttribute('data-attach'); }
            if (row.hasAttribute('data-encrypt') && row.getAttribute('data-encrypt')) { a.encrypt = row.getAttribute('data-encrypt'); }
            attributes.push(a);
        });
        if (attributes.length) { collected.Attribute = attributes; }

        // Event reports.
        var reports = [];
        root.querySelectorAll('.om-report').forEach(function (rep) {
            if (rep.dataset.removed === '1') { return; }
            var rd = dist('om-report', rep);
            reports.push({
                import_report: true,
                name: rep.getAttribute('data-name'),
                content: rep.querySelector('.om-report-content').value,
                uuid: rep.getAttribute('data-uuid'),
                distribution: rd.distribution,
                sharing_group_id: rd.sharing_group_id
            });
        });
        if (reports.length) { collected.EventReport = reports; }

        document.getElementById('ResolvedJsonObject').value = JSON.stringify(collected);
        submitBtn.disabled = true;
        fetch(form.getAttribute('action'), {
            method: 'POST',
            body: new FormData(form),
            headers: { 'X-Requested-With': 'XMLHttpRequest' }
        })
        .then(function (r) { return r.text(); })
        .then(function () { window.location = baseurl + '/events/view2/' + EVENT_ID; })
        .catch(function () { submitBtn.disabled = false; });
    });
})();
</script>
