<?php
/**
 *
 * Rendered body-only (freeTextImport sets layout=false when ajax && Overmind)
 * inside the chained modal opened by the "Populate from…" Freetext section
 * (openModalPostChained). jQuery-free.
 *
 * Vanilla JS builds the same JsonObject payload as the legacy
 * freetextSerializeAttributes() and AJAX-POSTs the tokened form to
 * /events/saveFreeText/{id}; on success we reload the event (view2).
 *
 * Vars: $event, $resultArray, $typeDefinitions, $typeCategoryMapping,
 *       $distributions, $sgs, $defaultAttributeDistribution, $importComment,
 *       $missingTldLists, $proposals, $isSiteAdmin.
 */

$eventId = (int)$event['Event']['id'];
$scope = !empty($proposals) ? __('proposals') : __('attributes');
$backUrl = !empty($backPath) ? ($baseurl . $backPath) : ($baseurl . '/events/populateFrom/' . $eventId);

// Distribution visuals (icon + colours), canonical for the whole theme.
$distMeta = $this->DistributionLevel->all();
$distFallback = $this->DistributionLevel->fallback();
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'event',
    'eyebrow' => __('Freetext Import'),
    'title' => __('Review detected %s', $scope),
    'titleBadge' => empty($resultArray)
        ? ''
        : '<span class="badge rounded-pill text-bg-light border">' . count($resultArray) . '</span>',
    'titleIcon' => 'fas fa-list-check',
    'icon' => 'fas fa-paragraph',
]) ?>

<!-- ── BODY ─────────────────────────────────────────────────── -->
<div class="p-4" style="background:var(--bs-tertiary-bg, #f8f9fa);">

    <?php if (!empty($missingTldLists)): ?>
        <div class="alert alert-warning d-flex align-items-start gap-2">
            <i class="fas fa-triangle-exclamation mt-1"></i>
            <div><?= __('You are missing warninglist(s) used to recognise TLDs (%s); some domains/hostnames/urls may be missed.', h(implode(', ', $missingTldLists))) ?></div>
        </div>
    <?php endif; ?>

    <?php if (!empty($resultArray)): ?>
        <p class="text-muted">
            <?= __('Below you can see the attributes that are to be created. Make sure that the categories and the types are correct, often several options will be offered based on an inconclusive automatic resolution.') ?>
        </p>
    <?php endif; ?>

    <?php if (empty($resultArray)): ?>
        <?php
            // The module's own explanation is surfaced here
            $emptyMsg = !empty($moduleError)
                ? $moduleError
                : __('No indicators were detected in the provided text.');
        ?>
        <div class="text-center text-muted py-5">
            <i class="fas fa-circle-info mb-3" style="font-size:2rem; opacity:.35;"></i>
            <p class="mb-1 fw-semibold text-body"><?= __('Nothing to import') ?></p>
            <p class="mb-0" style="max-width:32rem; margin-inline:auto;"><?= h($emptyMsg) ?></p>
        </div>
    <?php else: ?>

    <?php
    // Build the "change type from → to" options: for every multi-type detection,
    // map each candidate type to the others it could be switched to (legacy logic).
    $typeGroups = [];
    foreach ($resultArray as $rItem) {
        if (!empty($rItem['types']) && count($rItem['types']) > 1) {
            $typeGroups[implode('|', $rItem['types'])] = $rItem['types'];
        }
    }
    $optionsRearranged = [];
    foreach ($typeGroups as $group) {
        foreach ($group as $gi => $element) {
            $temp = $group;
            unset($temp[$gi]);
            if (!isset($optionsRearranged[$element])) {
                $optionsRearranged[$element] = [];
            }
            $optionsRearranged[$element] = array_values(array_unique(array_merge($optionsRearranged[$element], $temp)));
        }
    }

    // Tokened form: only the fields saveFreeText reads. The cards and the JS-only
    // bulk inputs carry no name, so FormData posts just these + the token.
    echo $this->Form->create('MispAttribute', [
        'url' => $baseurl . '/events/saveFreeText/' . $eventId,
        'id'  => 'freetextResolveForm',
    ]);
    ?>

    <!-- ── BULK ACTIONS ─────────────────────────────────────────── -->
    <div class="card border-0 shadow-sm mb-3">
        <div class="card-body py-3">
            <div class="text-event text-uppercase fw-semibold mb-3"
                 style="font-size:.6rem; letter-spacing:.1em;">
                <?= __('Bulk actions') ?>
            </div>
            <div class="row g-3 align-items-end">

                <?php if ($isSiteAdmin): ?>
                    <div class="col-12">
                        <div class="form-check">
                            <?= $this->Form->checkbox('Attribute.force', ['class' => 'form-check-input', 'id' => 'ftForce']) ?>
                            <label class="form-check-label" for="ftForce"><?= __('Create as proposals instead of attributes') ?></label>
                        </div>
                    </div>
                <?php endif; ?>

                <!-- apply a comment to all -->
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1"><?= __('Apply a comment to all') ?></label>
                    <div class="input-group input-group-sm">
                        <span class="input-group-text bg-white"><i class="fas fa-comment-dots text-muted"></i></span>
                        <input type="text" class="form-control" id="ftAllComments" placeholder="<?= __('Comment…') ?>">
                        <button type="button" class="btn btn-outline-secondary" id="ftApplyComments"><?= __('Apply') ?></button>
                    </div>
                </div>

                <?php if (!empty($optionsRearranged)): ?>
                <!-- switch the type of every matching attribute -->
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1"><?= __('Change type for all') ?></label>
                    <div class="input-group input-group-sm">
                        <select class="form-select" id="ftChangeFrom">
                            <?php foreach (array_keys($optionsRearranged) as $fromType): ?>
                                <option><?= h($fromType) ?></option>
                            <?php endforeach; ?>
                        </select>
                        <span class="input-group-text bg-white"><i class="fas fa-arrow-right text-muted"></i></span>
                        <select class="form-select" id="ftChangeTo"></select>
                        <button type="button" class="btn btn-outline-secondary" id="ftChangeApply"><?= __('Change all') ?></button>
                    </div>
                </div>
                <?php endif; ?>

            </div>
        </div>
    </div>

    <?php
    echo $this->Form->input('Attribute.JsonObject', [
        'label' => false, 'div' => false, 'type' => 'text',
        'id' => 'AttributeJsonObject', 'value' => '', 'style' => 'display:none;',
    ]);
    echo $this->Form->input('Attribute.default_comment', [
        'label' => false, 'div' => false, 'type' => 'text',
        'value' => $importComment, 'style' => 'display:none;',
    ]);
    echo $this->Form->end();
    ?>

    <?php
    $firstSg = !empty($sgs) ? (string)array_key_first($sgs) : '';
    ?>

    <div class="card border-0 shadow-sm mb-3">
        <div class="d-flex flex-wrap align-items-center gap-2 px-3 py-2 border-bottom">
            <div class="input-group input-group-sm" style="max-width:20rem;">
                <span class="input-group-text bg-white">
                    <i class="fas fa-magnifying-glass text-muted"></i>
                </span>
                <input type="text" class="form-control" id="ftFilter"
                       placeholder="<?= __('Filter by value, type or category…') ?>">
            </div>
            <span class="small text-muted ms-auto" id="ftCount"></span>
        </div>

        <div class="table-responsive">
        <table class="table table-sm table-hover align-middle mb-0">
            <thead>
                <tr class="small text-muted">
                    <th class="ps-3"><?= __('Value') ?></th>
                    <th><?= __('Category') ?></th>
                    <th><?= __('Type') ?></th>
                    <th class="text-center"><?= __('Distr.') ?></th>
                    <th class="text-center"><?= __('IDS') ?></th>
                    <th class="text-center"><?= __('Corr.') ?></th>
                    <th class="text-end pe-3"></th>
                </tr>
            </thead>
            <tbody id="ftCards">
            <?php foreach ($resultArray as $k => $item): ?>
                <?php
                // ── initial category selection (mirrors legacy logic) ──
                $catMap = $typeCategoryMapping[$item['default_type']];
                if (!isset($item['categories'])) {
                    if (isset($typeDefinitions[$item['default_type']])) {
                        $defaultCat = array_search(
                            $typeDefinitions[$item['default_type']]['default_category'],
                            $catMap
                        );
                    } else {
                        reset($catMap);
                        $defaultCat = key($catMap);
                    }
                } else {
                    $defaultCat = $item['category_default']
                        ?? array_search($item['categories'][0], $catMap);
                }
                $dist = $item['distribution'] ?? $defaultAttributeDistribution;
                if (!isset($distributions[$dist])) {
                    $dist = array_key_first($distributions);
                }
                $idsOn = !empty($item['to_ids']);
                $corrOn = empty($item['disable_correlation']);
                $comment = (isset($item['comment']) && $item['comment'] !== false)
                    ? $item['comment'] : '';
                $tags = (isset($item['tags']) && $item['tags'] !== false)
                    ? implode(',', $item['tags']) : '';
                $removeTags = (isset($item['remove_tags']) && $item['remove_tags'] !== false)
                    ? implode(',', $item['remove_tags']) : '';
                ?>

                <tr class="ft-row" data-row="<?= $k ?>"
                    data-value="<?= h($item['value']) ?>"
                    data-category="<?= h($defaultCat) ?>"
                    data-type="<?= h($item['default_type']) ?>"
                    data-types="<?= h(implode(',', $item['types'] ?? [])) ?>"
                <?php if (isset($item['categories'])): ?>
                    data-categories="<?= h(implode(',', $item['categories'])) ?>"
                <?php endif; ?>
                    data-ids="<?= $idsOn ? '1' : '0' ?>"
                    data-corr="<?= $corrOn ? '1' : '0' ?>"
                    data-dist="<?= h($dist) ?>"
                    data-sg="<?= h($firstSg) ?>"
                    data-comment="<?= h($comment) ?>"
                    data-tags="<?= h($tags) ?>"
                    data-remove-tags="<?= h($removeTags) ?>"
                <?php if (!empty($item['data'])): ?>
                    data-attachment="<?= h($item['data']) ?>"
                <?php endif; ?>
                <?php if (!empty($item['data_is_handled'])): ?> 
                    data-attachment-handled="<?= h($item['data_is_handled']) ?>"
                <?php endif; ?>>
                    <td class="ps-3" style="max-width:24rem;"><span class="ft-value font-monospace d-block text-truncate" title="<?= h($item['value']) ?>"><?= h($item['value']) ?></span><span class="ft-meta small text-muted d-block text-truncate"></span></td>
                    <td class="ft-cat-badge text-nowrap"><?= $this->element('genericElementsBS5/Badges/category', ['category' => $defaultCat, 'full' => false]) ?></td>
                    <td class="ft-type-badge text-nowrap"><?= $this->element('genericElementsBS5/Badges/type', ['type' => $item['default_type']]) ?></td>
                    <td class="ft-dist-badge text-center"><?= $this->element('genericElementsBS5/Badges/distribution', ['distribution' => $dist, 'full' => false]) ?></td>
                    <td class="text-center"><i class="fas fa-shield-halved ft-ids<?= $idsOn ? '' : ' opacity-25' ?>" role="button" title="<?= __('Send to IDS') ?>"<?= $idsOn ? ' style="color:var(--bs-warning);"' : '' ?>></i></td>
                    <td class="text-center"><i class="fas <?= $corrOn ? 'fa-link' : 'fa-link-slash opacity-25' ?> ft-corr" role="button" title="<?= __('Correlate') ?>"<?= $corrOn ? ' style="color:var(--bs-success);"' : '' ?>></i></td>
                    <td class="text-end pe-3 text-nowrap"><?php if (!empty($item['related'])): ?><span class="badge rounded-pill text-bg-light border ft-related" title="<?= __('Already seen in %s event(s)', count($item['related'])) ?>" data-related="<?= h(json_encode(array_map(function ($r) { return (int)$r['Event']['id']; }, $item['related']))) ?>"><i class="fas fa-clone me-1"></i><?= count($item['related']) ?></span><?php endif; ?><button type="button" class="btn btn-sm btn-light ft-edit-btn" title="<?= __('Edit') ?>"><i class="fas fa-pen"></i></button><button type="button" class="btn btn-sm btn-light text-danger ft-remove" title="<?= __('Remove') ?>"><i class="fas fa-trash"></i></button></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        </div>
    </div>

    <template id="ftEditTemplate">
        <div class="p-3" style="background:var(--bs-tertiary-bg, #f8f9fa);">
            <div class="row g-3">
                <div class="col-12">
                    <label class="form-label small text-muted mb-1"><?= __('Value') ?></label>
                    <input type="text"
                           class="form-control form-control-sm font-monospace ft-f-value">
                </div>
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1"><?= __('Category') ?></label>
                    <select class="form-select form-select-sm ft-f-category"></select>
                </div>
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1"><?= __('Type') ?></label>
                    <select class="form-select form-select-sm ft-f-type"></select>
                </div>
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1"><?= __('Distribution') ?></label>
                    <select class="form-select form-select-sm ft-f-dist">
                        <?php foreach ($distributions as $dKey => $dVal): ?>
                            <option value="<?= h($dKey) ?>"><?= h($dVal) ?></option>
                        <?php endforeach; ?>
                    </select>
                    <div class="ft-f-sg-wrap d-none">
                        <select class="form-select form-select-sm mt-2 ft-f-sg">
                            <?php foreach ($sgs as $sgKey => $sgVal): ?>
                                <option value="<?= h($sgKey) ?>"><?= h($sgVal) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1"><?= __('Comment') ?></label>
                    <input type="text" class="form-control form-control-sm ft-f-comment">
                </div>
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1"><?= __('Tags') ?></label>
                    <input type="text" class="form-control form-control-sm ft-f-tags"
                           placeholder="tag1, tag2">
                </div>
                <div class="col-md-6">
                    <label class="form-label small text-muted mb-1">
                        <?= __('Tags to remove') ?>
                    </label>
                    <input type="text" class="form-control form-control-sm ft-f-remove-tags"
                           placeholder="tag1, tag2"
                           title="<?= __('These tags are removed from the attribute already in the event that carries this value, if it has them.') ?>">
                </div>
                <div class="col-12 ft-f-related d-none">
                    <label class="form-label small text-muted mb-1"><?= __('Similar in') ?></label>
                    <div class="d-flex flex-wrap gap-1 ft-f-related-list"></div>
                </div>
            </div>
            <div class="d-flex justify-content-end mt-3">
                <button type="button" class="btn btn-sm btn-outline-secondary ft-f-close">
                    <i class="fas fa-check me-1"></i><?= __('Done') ?>
                </button>
            </div>
        </div>
    </template>

    <?php endif; ?>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'event',
        'meta' => [['label' => __('Event'), 'id' => $eventId]],
        'buttons' => [[
            'label' => __('Back'),
            'icon' => 'fas fa-arrow-left',
            'attrs' => ['onclick' => sprintf("openModalChained('%s');", $backUrl)],
        ]],
        'submit' => empty($resultArray) ? false : [
            'label' => __('Create %s', $scope),
            'id' => 'ftSubmit',
            'type' => 'button',
        ],
    ]) ?>
</div>

<script>
(function () {
    var EVENT_ID = <?= $eventId ?>;
    var typeCategoryMapping = <?= json_encode($typeCategoryMapping) ?>;
    var distMeta = <?= json_encode($distMeta, JSON_FORCE_OBJECT) ?>;
    var distFallback = <?= json_encode($distFallback) ?>;
    var L = {
        ids:  <?= json_encode(__('Send to IDS')) ?>,
        corr: <?= json_encode(__('Correlate')) ?>,
        showing: <?= json_encode(__('%s of %s shown')) ?>,
        saveFailed: <?= json_encode(__('Could not create the %s. Please reopen the freetext import and try again.', $scope)) ?>
    };
    var optionsRearranged = <?= json_encode($optionsRearranged ?? new stdClass()) ?>;

    var listEl = document.getElementById('ftCards');
    if (!listEl) { return; }
    var tpl = document.getElementById('ftEditTemplate');

    // Never submit the tokened form natively: the Create button drives a fetch
    // POST with the JS-built JsonObject instead.
    var formEl = document.getElementById('freetextResolveForm');
    if (formEl) { formEl.addEventListener('submit', function (e) { e.preventDefault(); }); }

    function rows() {
        return Array.prototype.slice.call(listEl.querySelectorAll('.ft-row'));
    }
    function activeRows() {
        return rows().filter(function (r) { return r.dataset.removed !== '1'; });
    }

    // ── painting the compact row ──────────────────────────────────
    function distConfig(level) {
        return distMeta[String(level)] || distFallback;
    }
    function paintRow(row) {
        var d = row.dataset;

        var val = row.querySelector('.ft-value');
        val.textContent = d.value;
        val.title = d.value;

        var cat = row.querySelector('.ft-cat-badge p');
        if (cat) { cat.textContent = d.category; }
        var typ = row.querySelector('.ft-type-badge p');
        if (typ) { typ.textContent = d.type; }

        var cfg = distConfig(d.dist);
        var badge = row.querySelector('.ft-dist-badge .badge');
        if (badge) {
            badge.style.backgroundColor = cfg.bg;
            badge.style.color = cfg.color;
            badge.style.border = '1px solid ' + cfg.color + '20';
            badge.title = cfg.label;
            badge.querySelector('i').className = cfg.icon;
        }

        var idsOn = d.ids === '1';
        var idsIcon = row.querySelector('.ft-ids');
        idsIcon.classList.toggle('opacity-25', !idsOn);
        idsIcon.style.color = idsOn ? 'var(--bs-warning)' : '';

        var corrOn = d.corr === '1';
        var corrIcon = row.querySelector('.ft-corr');
        corrIcon.classList.toggle('fa-link', corrOn);
        corrIcon.classList.toggle('fa-link-slash', !corrOn);
        corrIcon.classList.toggle('opacity-25', !corrOn);
        corrIcon.style.color = corrOn ? 'var(--bs-success)' : '';

        // second line: whatever the row carries that the columns do not show
        var bits = [];
        if (d.comment) { bits.push(d.comment); }
        if (d.tags) { bits.push('#' + d.tags.split(',').join(' #')); }
        if (d.removeTags) { bits.push('−' + d.removeTags.split(',').join(' −')); }
        var meta = row.querySelector('.ft-meta');
        meta.textContent = bits.join('  ·  ');
        meta.title = meta.textContent;
    }
    rows().forEach(paintRow);

    // ── filter ────────────────────────────────────────────────────
    var filterEl = document.getElementById('ftFilter');
    var countEl = document.getElementById('ftCount');
    function applyFilter() {
        var q = (filterEl ? filterEl.value : '').trim().toLowerCase();
        var shown = 0, total = 0;
        rows().forEach(function (row) {
            if (row.dataset.removed === '1') {
                row.classList.add('d-none');
                closeEditor(row);
                return;
            }
            total++;
            var d = row.dataset;
            var hit = !q
                || d.value.toLowerCase().indexOf(q) !== -1
                || d.type.toLowerCase().indexOf(q) !== -1
                || d.category.toLowerCase().indexOf(q) !== -1
                || (d.comment && d.comment.toLowerCase().indexOf(q) !== -1)
                || (d.tags && d.tags.toLowerCase().indexOf(q) !== -1);
            row.classList.toggle('d-none', !hit);
            if (!hit) { closeEditor(row); } else { shown++; }
        });
        if (countEl) {
            countEl.textContent = L.showing
                .replace('%s', shown).replace('%s', total);
        }
    }
    if (filterEl) { filterEl.addEventListener('input', applyFilter); }
    applyFilter();

    // ── the editor, cloned on demand ──────────────────────────────
    function editorOf(row) {
        var next = row.nextElementSibling;
        return (next && next.classList.contains('ft-editor')) ? next : null;
    }
    function closeEditor(row) {
        var ed = editorOf(row);
        if (ed) { ed.remove(); }
        row.classList.remove('table-active');
        var btn = row.querySelector('.ft-edit-btn i');
        if (btn) { btn.className = 'fas fa-pen'; }
    }
    function catsFor(row) {
        if (row.dataset.categories) { return row.dataset.categories.split(','); }
        var map = typeCategoryMapping[row.dataset.type];
        return map ? Object.keys(map) : [];
    }
    function fillSelect(sel, values, current) {
        sel.innerHTML = '';
        values.forEach(function (v) {
            var o = document.createElement('option');
            o.value = v;
            o.textContent = v;
            if (v === current) { o.selected = true; }
            sel.appendChild(o);
        });
    }
    function openEditor(row) {
        if (editorOf(row)) { closeEditor(row); return; }
        if (!tpl) { return; }
        var tr = document.createElement('tr');
        tr.className = 'ft-editor';
        var td = document.createElement('td');
        td.colSpan = row.children.length;
        td.className = 'p-0';
        td.appendChild(tpl.content.cloneNode(true));
        tr.appendChild(td);
        row.after(tr);

        var d = row.dataset;
        var q = function (c) { return tr.querySelector(c); };

        q('.ft-f-value').value = d.value;
        q('.ft-f-comment').value = d.comment || '';
        q('.ft-f-tags').value = d.tags || '';
        q('.ft-f-remove-tags').value = d.removeTags || '';
        fillSelect(q('.ft-f-type'), (d.types || d.type).split(','), d.type);
        fillSelect(q('.ft-f-category'), catsFor(row), d.category);

        var distSel = q('.ft-f-dist');
        var sgWrap = q('.ft-f-sg-wrap');
        var sgSel = q('.ft-f-sg');
        distSel.value = d.dist;
        if (sgSel && d.sg) { sgSel.value = d.sg; }
        function revealSg() {
            sgWrap.classList.toggle('d-none', String(distSel.value) !== '4');
        }
        revealSg();

        var related = row.querySelector('.ft-related');
        if (related) {
            var wrap = q('.ft-f-related');
            var list = q('.ft-f-related-list');
            JSON.parse(related.dataset.related).forEach(function (id) {
                var a = document.createElement('a');
                a.href = '<?= $baseurl ?>/events/view2/' + id;
                a.target = '_blank';
                a.className = 'badge bg-light text-dark border text-decoration-none';
                a.textContent = '#' + id;
                list.appendChild(a);
            });
            wrap.classList.remove('d-none');
        }

        // every control writes straight back into the row's dataset
        tr.addEventListener('input', function (e) {
            var t = e.target;
            if (t.classList.contains('ft-f-value')) { d.value = t.value; }
            else if (t.classList.contains('ft-f-comment')) { d.comment = t.value; }
            else if (t.classList.contains('ft-f-tags')) { d.tags = t.value; }
            else if (t.classList.contains('ft-f-remove-tags')) { d.removeTags = t.value; }
            else { return; }
            paintRow(row);
        });
        tr.addEventListener('change', function (e) {
            var t = e.target;
            if (t.classList.contains('ft-f-type')) {
                d.type = t.value;
                // the categories a type allows change with it
                var cats = catsFor(row);
                if (cats.indexOf(d.category) === -1) { d.category = cats[0] || ''; }
                fillSelect(q('.ft-f-category'), cats, d.category);
            } else if (t.classList.contains('ft-f-category')) {
                d.category = t.value;
            } else if (t.classList.contains('ft-f-dist')) {
                d.dist = t.value;
                revealSg();
            } else if (t.classList.contains('ft-f-sg')) {
                d.sg = t.value;
            } else {
                return;
            }
            paintRow(row);
        });
        q('.ft-f-close').addEventListener('click', function () { closeEditor(row); });

        row.classList.add('table-active');
        var btn = row.querySelector('.ft-edit-btn i');
        if (btn) { btn.className = 'fas fa-chevron-up'; }
        q('.ft-f-value').focus();
    }

    // ── row actions ───────────────────────────────────────────────
    listEl.addEventListener('click', function (e) {
        var row = e.target.closest('.ft-row');
        if (!row) { return; }

        if (e.target.closest('.ft-ids')) {
            row.dataset.ids = row.dataset.ids === '1' ? '0' : '1';
            paintRow(row);
            return;
        }
        if (e.target.closest('.ft-corr')) {
            row.dataset.corr = row.dataset.corr === '1' ? '0' : '1';
            paintRow(row);
            return;
        }
        if (e.target.closest('.ft-remove')) {
            row.dataset.removed = '1';
            closeEditor(row);
            row.classList.add('d-none');
            applyFilter();
            return;
        }
        if (e.target.closest('.ft-edit-btn')) {
            openEditor(row);
        }
    });

    // ── bulk comment ──────────────────────────────────────────────
    var applyBtn = document.getElementById('ftApplyComments');
    if (applyBtn) {
        applyBtn.addEventListener('click', function () {
            var v = document.getElementById('ftAllComments').value;
            activeRows().forEach(function (row) {
                row.dataset.comment = v;
                closeEditor(row);
                paintRow(row);
            });
        });
    }

    // ── bulk "change type from → to" ──────────────────────────────
    var changeFrom  = document.getElementById('ftChangeFrom');
    var changeTo    = document.getElementById('ftChangeTo');
    var changeApply = document.getElementById('ftChangeApply');
    function refreshChangeTo() {
        if (!changeFrom || !changeTo) { return; }
        fillSelect(changeTo, optionsRearranged[changeFrom.value] || [], null);
    }
    if (changeFrom) {
        changeFrom.addEventListener('change', refreshChangeTo);
        refreshChangeTo();
    }
    if (changeApply) {
        changeApply.addEventListener('click', function () {
            var from = changeFrom.value, to = changeTo.value;
            if (!to) { return; }
            activeRows().forEach(function (row) {
                var d = row.dataset;
                if (d.type !== from) { return; }
                if ((d.types || '').split(',').indexOf(to) === -1) { return; }
                d.type = to;
                var cats = catsFor(row);
                if (cats.indexOf(d.category) === -1) { d.category = cats[0] || ''; }
                closeEditor(row);
                paintRow(row);
            });
            applyFilter();
        });
    }

    // ── submit ────────────────────────────────────────────────────
    var submitBtn = document.getElementById('ftSubmit');
    if (submitBtn) {
        submitBtn.addEventListener('click', function () {
            var arr = activeRows().map(function (row) {
                var d = row.dataset;
                return {
                    value: d.value,
                    category: d.category,
                    type: d.type,
                    to_ids: d.ids === '1',
                    disable_correlation: d.corr !== '1',
                    comment: d.comment || '',
                    distribution: d.dist,
                    sharing_group_id: d.sg || '',
                    data: d.attachment || '',
                    data_is_handled: d.attachmentHandled || '',
                    tags: d.tags || '',
                    remove_tags: d.removeTags || ''
                };
            });
            if (arr.length === 0) { return; }
            document.getElementById('AttributeJsonObject').value = JSON.stringify(arr);
            var form = document.getElementById('freetextResolveForm');
            submitBtn.disabled = true;
            fetch(form.getAttribute('action'), {
                method: 'POST',
                body: new FormData(form),
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            })
            // Reload only on success
            .then(function (r) {
                if (!r.ok) { throw new Error(r.status); }
                returnToEventView(EVENT_ID);
            })
            .catch(function () {
                submitBtn.disabled = false;
                if (typeof showToast === 'function') {
                    showToast(L.saveFailed, 'danger');
                }
            });
        });
    }
})();
</script>
