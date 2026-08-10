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

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--event);">
    <div>
        <div class="text-event text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Freetext Import') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-list-check text-event" style="font-size:1.25rem;"></i>
            <?= __('Review detected %s', $scope) ?>
            <?php if (!empty($resultArray)): ?>
                <span class="badge rounded-pill text-bg-light border"><?= count($resultArray) ?></span>
            <?php endif; ?>
        </h4>
    </div>
    <span class="fas fa-paragraph text-event" style="font-size:2rem; opacity:.5;"></span>
</div>

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

    <div id="ftCards">
        <?php foreach ($resultArray as $k => $item): ?>
            <?php
            // ── initial category selection (mirrors legacy logic) ──
            $catMap = $typeCategoryMapping[$item['default_type']];
            if (!isset($item['categories'])) {
                if (isset($typeDefinitions[$item['default_type']])) {
                    $defaultCat = array_search($typeDefinitions[$item['default_type']]['default_category'], $catMap);
                } else {
                    reset($catMap);
                    $defaultCat = key($catMap);
                }
            } else {
                $defaultCat = $item['category_default'] ?? array_search($item['categories'][0], $catMap);
            }
            $dist = $item['distribution'] ?? $defaultAttributeDistribution;
            if (!isset($distributions[$dist])) {
                $dist = array_key_first($distributions);
            }
            $dm = $distMeta[$dist] ?? $distFallback;
            $idsOn = !empty($item['to_ids']);
            $corrOn = empty($item['disable_correlation']);
            ?>
            <div class="card border-0 shadow-sm mb-3 ft-card" data-row="<?= $k ?>">
                <div class="card-body">

                    <!-- value + remove -->
                    <div class="d-flex align-items-center gap-2 mb-2">
                        <i class="misp-icon misp-icon-attribute misp-hexagone" style="font-size:1.8rem; opacity:.6;"></i>
                        <input type="text" class="form-control fw-semibold ft-value font-monospace"
                               value="<?= h($item['value']) ?>">
                        <button type="button" class="btn btn-sm btn-light text-danger ft-remove"
                                title="<?= __('Remove') ?>"><i class="fas fa-trash"></i></button>
                    </div>

                    <!-- comment (full width, right under the value) -->
                    <div class="input-group input-group-sm mb-3">
                        <span class="input-group-text bg-white"><i class="fas fa-comment text-muted"></i></span>
                        <input type="text" class="form-control ft-comment" placeholder="<?= __('Comment') ?>"
                               value="<?= (isset($item['comment']) && $item['comment'] !== false) ? h($item['comment']) : '' ?>">
                    </div>

                    <!-- category + type (category first) -->
                    <div class="row g-2 mb-3">
                        <div class="col-sm-6">
                            <label class="form-label small text-muted mb-1"><?= __('Category') ?></label>
                            <select class="form-select form-select-sm ft-category">
                                <?php foreach ($catMap as $category): ?>
                                    <?php if (isset($item['categories']) && !in_array($category, $item['categories'], true)) continue; ?>
                                    <option<?= $category == $defaultCat ? ' selected' : '' ?>><?= h($category) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="col-sm-6">
                            <label class="form-label small text-muted mb-1"><?= __('Type') ?></label>
                            <select class="form-select form-select-sm ft-type">
                                <?php foreach (($item['types'] ?? []) as $type): ?>
                                    <option<?= $type === $item['default_type'] ? ' selected' : '' ?>><?= h($type) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>

                    <!-- distribution: clickable cards (same as Add Object) -->
                    <div class="mb-3">
                        <label class="form-label small text-muted mb-1"><?= __('Distribution') ?></label>
                        <input type="hidden" class="ft-dist" value="<?= h($dist) ?>">
                        <div class="row g-2 ft-dist-row">
                            <?php foreach ($distributions as $dKey => $dVal): ?>
                                <?php
                                    $m = $distMeta[$dKey] ?? $distFallback;
                                    $sel = ($dKey == $dist);
                                ?>
                                <div class="col ft-dist-card" data-dist-value="<?= h($dKey) ?>" style="cursor:pointer;">
                                    <div class="border rounded p-2 d-flex flex-column align-items-center gap-1 h-100 text-center ft-dist-inner"
                                         style="transition:border-color .15s,background .15s;<?= $sel ? 'border-color:var(--event);background:rgba(24,146,177,.08);' : 'border-color:#d8dde3;' ?>">
                                        <span class="d-inline-flex align-items-center justify-content-center rounded-circle mb-1"
                                              style="width:1.8rem;height:1.8rem;background:<?= h($m['bg']) ?>;border:1px solid <?= h($m['color']) ?>30;">
                                            <i class="<?= h($m['icon']) ?>" style="color:<?= h($m['color']) ?>;font-size:.7rem;"></i>
                                        </span>
                                        <span class="fw-bold lh-sm" style="font-size:.68rem;"><?= h($dVal) ?></span>
                                    </div>
                                </div>
                            <?php endforeach; ?>
                        </div>
                        <select class="form-select form-select-sm ft-sg mt-2" style="<?= $dist == 4 ? '' : 'display:none;' ?>">
                            <?php foreach ($sgs as $sgKey => $sgVal): ?>
                                <option value="<?= h($sgKey) ?>"><?= h($sgVal) ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <!-- IDS / Correlate badges (same style as the attribute index card view) -->
                    <div class="d-flex flex-wrap align-items-center gap-2 mb-3">
                        <span class="badge d-inline-flex align-items-center gap-1 px-2 py-1 border ft-ids <?= $idsOn ? 'border-warning text-warning' : 'border-secondary text-secondary' ?>"
                              role="button" data-on="<?= $idsOn ? '1' : '0' ?>" style="background:transparent;font-size:.8rem;cursor:pointer;">
                            <i class="fas fa-shield-halved"></i>
                            <span class="ft-ids-label"><?= $idsOn ? __('IDS') : __('No IDS') ?></span>
                        </span>
                        <span class="badge d-inline-flex align-items-center gap-1 px-2 py-1 border ft-corr <?= $corrOn ? 'border-success text-success' : 'border-secondary text-secondary' ?>"
                              role="button" data-on="<?= $corrOn ? '1' : '0' ?>" style="background:transparent;font-size:.8rem;cursor:pointer;">
                            <i class="fas <?= $corrOn ? 'fa-link' : 'fa-link-slash' ?>"></i>
                            <span class="ft-corr-label"><?= $corrOn ? __('Correlation On') : __('Correlation Off') ?></span>
                        </span>
                    </div>

                    <!-- tags + galaxies (galaxies disabled — backend not ready) -->
                    <div class="row g-2">
                        <div class="col-sm-6">
                            <label class="form-label small text-muted mb-1"><?= __('Tags') ?></label>
                            <div class="input-group input-group-sm">
                                <span class="input-group-text bg-white"><i class="misp-icon misp-icon-tag misp-simple text-muted"></i></span>
                                <input type="text" class="form-control ft-tags" placeholder="tag1, tag2"
                                       value="<?= (isset($item['tags']) && $item['tags'] !== false) ? h(implode(',', $item['tags'])) : '' ?>">
                            </div>
                        </div>
                        <div class="col-sm-6">
                            <label class="form-label small text-muted mb-1">
                                <?= __('Galaxies') ?>
                            </label>
                            <div class="input-group input-group-sm">
                                <span class="input-group-text bg-white"><i class="misp-icon misp-icon-galaxy misp-simple text-muted"></i></span>
                                <input type="text" class="form-control" disabled>
                            </div>
                        </div>
                    </div>

                    <?php if (!empty($item['related'])): ?>
                        <div class="mt-3 small d-flex flex-wrap align-items-center gap-1">
                            <span class="text-muted me-1"><i class="fas fa-clone me-1"></i><?= __('Similar in:') ?></span>
                            <?php foreach ($item['related'] as $relation): ?>
                                <a href="<?= $baseurl ?>/events/view2/<?= h($relation['Event']['id']) ?>" target="_blank"
                                   class="badge bg-light text-dark border text-decoration-none"
                                   title="<?= h($relation['Event']['info'] ?? '') ?>">#<?= h($relation['Event']['id']) ?></a>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>

                    <!-- hidden per-row data (read by JS only; no name → not posted) -->
                    <input type="hidden" class="ft-data" value="<?= isset($item['data']) ? h($item['data']) : '' ?>">
                    <input type="hidden" class="ft-datahandled" value="<?= isset($item['data_is_handled']) ? h($item['data_is_handled']) : '' ?>">
                </div>
            </div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center mt-2 pt-3 flex-wrap gap-2"
         style="border-top:1px solid var(--bs-border-color, #dee2e6);">
        <div class="text-muted" style="font-size:.75rem;">
            <?= __('Event') ?>: <strong class="text-body">#<?= h($eventId) ?></strong>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    onclick="openModalChained('<?= $backUrl ?>');">
                <i class="fas fa-arrow-left me-1"></i><?= __('Back') ?>
            </button>
            <button type="button" class="btn btn-outline-secondary btn-sm" data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?php if (!empty($resultArray)): ?>
                <button type="button" class="btn btn-event btn-sm text-white" id="ftSubmit">
                    <i class="fas fa-circle-plus me-1"></i><?= __('Create %s', $scope) ?>
                </button>
            <?php endif; ?>
        </div>
    </div>
</div>

<script>
(function () {
    var EVENT_ID = <?= $eventId ?>;
    var typeCategoryMapping = <?= json_encode($typeCategoryMapping) ?>;
    var L = {
        idsOn:  <?= json_encode(__('IDS')) ?>,
        idsOff: <?= json_encode(__('No IDS')) ?>,
        corrOn: <?= json_encode(__('Correlation On')) ?>,
        corrOff:<?= json_encode(__('Correlation Off')) ?>,
        saveFailed: <?= json_encode(__('Could not create the %s. Please reopen the freetext import and try again.', $scope)) ?>
    };
    var optionsRearranged = <?= json_encode($optionsRearranged ?? new stdClass()) ?>;

    var cardsEl = document.getElementById('ftCards');
    if (!cardsEl) { return; }

    // Never submit the tokened form natively
    // Create button drives a fetch POST with the JS-built JsonObject instead.
    var formEl = document.getElementById('freetextResolveForm');
    if (formEl) { formEl.addEventListener('submit', function (e) { e.preventDefault(); }); }

    function activeCards() {
        return Array.prototype.filter.call(
            cardsEl.querySelectorAll('.ft-card'),
            function (c) { return c.dataset.removed !== '1'; }
        );
    }

    // IDS badge 
    function paintIds(b) {
        var on = b.dataset.on === '1';
        b.classList.toggle('border-warning', on);
        b.classList.toggle('text-warning', on);
        b.classList.toggle('border-secondary', !on);
        b.classList.toggle('text-secondary', !on);
        b.querySelector('.ft-ids-label').textContent = on ? L.idsOn : L.idsOff;
    }
    // Correlate badge
    function paintCorr(b) {
        var on = b.dataset.on === '1';
        b.classList.toggle('border-success', on);
        b.classList.toggle('text-success', on);
        b.classList.toggle('border-secondary', !on);
        b.classList.toggle('text-secondary', !on);
        var icon = b.querySelector('i');
        icon.classList.toggle('fa-link', on);
        icon.classList.toggle('fa-link-slash', !on);
        b.querySelector('.ft-corr-label').textContent = on ? L.corrOn : L.corrOff;
    }

    cardsEl.addEventListener('click', function (e) {
        var ids = e.target.closest('.ft-ids');
        if (ids) { ids.dataset.on = ids.dataset.on === '1' ? '0' : '1'; paintIds(ids); return; }
        var corr = e.target.closest('.ft-corr');
        if (corr) { corr.dataset.on = corr.dataset.on === '1' ? '0' : '1'; paintCorr(corr); return; }
        var rm = e.target.closest('.ft-remove');
        if (rm) {
            var card = rm.closest('.ft-card');
            card.dataset.removed = '1';
            card.style.display = 'none';
            return;
        }
        // distribution card chosen
        var distCard = e.target.closest('.ft-dist-card');
        if (distCard) {
            var card = distCard.closest('.ft-card');
            var level = distCard.dataset.distValue;
            card.querySelectorAll('.ft-dist-inner').forEach(function (inner) {
                inner.style.borderColor = '#d8dde3';
                inner.style.background = '';
            });
            var inner = distCard.querySelector('.ft-dist-inner');
            inner.style.borderColor = 'var(--event)';
            inner.style.background = 'rgba(24,146,177,.08)';
            card.querySelector('.ft-dist').value = level;
            var sg = card.querySelector('.ft-sg');
            if (sg) { sg.style.display = (parseInt(level, 10) === 4) ? '' : 'none'; }
        }
    });

    // Type change → repopulate the category select for that card.
    cardsEl.addEventListener('change', function (e) {
        if (!e.target.classList.contains('ft-type')) { return; }
        var card = e.target.closest('.ft-card');
        var catSel = card.querySelector('.ft-category');
        var cats = typeCategoryMapping[e.target.value] ? Object.keys(typeCategoryMapping[e.target.value]) : [];
        var current = catSel.value;
        catSel.innerHTML = '';
        cats.forEach(function (c) {
            var o = document.createElement('option');
            o.value = c; o.textContent = c;
            if (c === current) { o.selected = true; }
            catSel.appendChild(o);
        });
    });

    // Bulk comment.
    var applyBtn = document.getElementById('ftApplyComments');
    if (applyBtn) {
        applyBtn.addEventListener('click', function () {
            var v = document.getElementById('ftAllComments').value;
            activeCards().forEach(function (c) { c.querySelector('.ft-comment').value = v; });
        });
    }

    // Bulk "change type from → to": switch every card whose type === from (and
    // that offers `to`) to `to`, then refresh its category (same as legacy).
    var changeFrom  = document.getElementById('ftChangeFrom');
    var changeTo    = document.getElementById('ftChangeTo');
    var changeApply = document.getElementById('ftChangeApply');
    function refreshChangeTo() {
        if (!changeFrom || !changeTo) { return; }
        var alts = optionsRearranged[changeFrom.value] || [];
        changeTo.innerHTML = '';
        alts.forEach(function (t) {
            var o = document.createElement('option');
            o.value = t; o.textContent = t;
            changeTo.appendChild(o);
        });
    }
    if (changeFrom) {
        changeFrom.addEventListener('change', refreshChangeTo);
        refreshChangeTo();
    }
    if (changeApply) {
        changeApply.addEventListener('click', function () {
            var from = changeFrom.value, to = changeTo.value;
            if (!to) { return; }
            activeCards().forEach(function (c) {
                var sel = c.querySelector('.ft-type');
                var hasTo = Array.prototype.some.call(sel.options, function (o) { return o.value === to; });
                if (sel.value === from && hasTo) {
                    sel.value = to;
                    sel.dispatchEvent(new Event('change', { bubbles: true }));
                }
            });
        });
    }

    // Submit: build the JsonObject and AJAX-POST the tokened form, then reload.
    var submitBtn = document.getElementById('ftSubmit');
    if (submitBtn) {
        submitBtn.addEventListener('click', function () {
            var arr = activeCards().map(function (c) {
                return {
                    value: c.querySelector('.ft-value').value,
                    category: c.querySelector('.ft-category').value,
                    type: c.querySelector('.ft-type').value,
                    to_ids: c.querySelector('.ft-ids').dataset.on === '1',
                    disable_correlation: c.querySelector('.ft-corr').dataset.on !== '1',
                    comment: c.querySelector('.ft-comment').value,
                    distribution: c.querySelector('.ft-dist').value,
                    sharing_group_id: c.querySelector('.ft-sg').value,
                    data: c.querySelector('.ft-data').value,
                    data_is_handled: c.querySelector('.ft-datahandled').value,
                    tags: c.querySelector('.ft-tags').value
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
                window.location = baseurl + '/events/view2/' + EVENT_ID;
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
