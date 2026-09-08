<?php
$m       = $modelSelection;
$action  = $this->request->params['action'];
$isEdit  = $action === 'edit';
$data    = $this->request->data[$m] ?? [];

$styles = [
    'Note' => [
        'color' => 'primary',
        'icon'  => 'misp-icon misp-icon-analyst-note misp-simple',
        'label' => __('Note'),
        'desc'  => __('Attach a free-text annotation to a MISP data point.'),
    ],
    'Opinion' => [
        'color' => 'success',
        'icon'  => 'misp-icon misp-icon-analyst-opinion misp-simple',
        'label' => __('Opinion'),
        'desc'  => __('Rate your confidence (0–100) in a data point, with a justification.'),
    ],
    'Relationship' => [
        'color' => 'correlation',
        'icon'  => 'fas fa-diagram-project',
        'label' => __('Relationship'),
        'desc'  => __('Create a typed link from a data point to another one.'),
    ],
];
$s     = $styles[$m] ?? $styles['Note'];
$color = $s['color'];

$presetTarget = !$isEdit && !empty($data['object_type']);

$formUrl = $isEdit
    ? $baseurl . '/analystData/edit/' . $m . '/' . h($id)
    : ($presetTarget
        ? $baseurl . '/analystData/add/' . $m . '/' . h($data['object_uuid']) . '/' . h($data['object_type'])
        : $baseurl . '/analystData/add/' . $m);

$currentDistribution = isset($data['distribution'])
    ? (int)$data['distribution']
    : (int)$initialDistribution;

// Flatten the "- No language -" + RFC5646 optgroup into a flat option list.
$languageOptions = ['' => __('- No language -')];
if (!empty($languageRFC5646[0]) && is_array($languageRFC5646[0])) {
    $languageOptions += $languageRFC5646[0];
}

echo $this->Form->create($m, [
    'url'        => $formUrl,
    'novalidate' => true,
    'id'         => 'analystDataForm',
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => $color,
    'eyebrow' => __('Analyst Data'),
    'title' => $isEdit ? __('Edit %s', $s['label']) : __('Add %s', $s['label']),
    'description' => $s['desc'],
    'icon' => $s['icon'],
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">
    <div class="d-flex flex-column gap-4">

        <!-- ── TARGET ──────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-<?= $color ?> fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Target object') ?>
                <?php if (!$isEdit): ?>
                    <span class="badge bg-<?= $color ?>" style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                <?php endif; ?>
            </div>

            <?php if ($isEdit || $presetTarget): ?>
                <div class="border rounded px-3 py-2 d-flex align-items-center gap-2 bg-light">
                    <span class="badge bg-secondary-subtle text-secondary-emphasis">
                        <?= h($data['object_type'] ?? '') ?>
                    </span>
                    <code class="small"><?= h($data['object_uuid'] ?? '') ?></code>
                </div>

            <?php else: ?>
                <div class="d-flex gap-3 flex-wrap">
                    <div style="min-width:12rem;">
                        <?= $this->Form->select('object_type', $dropdownData['valid_targets'], [
                            'class'   => 'form-select tom-select',
                            'empty'   => __('Select type…'),
                            'default' => $data['object_type'] ?? null,
                        ]) ?>
                    </div>
                    <div class="flex-grow-1" style="min-width:18rem;">
                        <?= $this->Form->text('object_uuid', [
                            'class'       => 'form-control',
                            'placeholder' => 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX',
                            'default'     => $data['object_uuid'] ?? null,
                        ]) ?>
                    </div>
                </div>
            <?php endif; ?>
        </div>

        <!-- ── DISTRIBUTION / SHARING GROUP ────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-<?= $color ?> fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Distribution / Sharing Group') ?>
            </div>
            <div class="d-flex gap-3">
                <div class="flex-fill">
                    <?= $this->Form->select('distribution', $dropdownData['distributionLevels'], [
                        'class' => 'form-select',
                        'id'    => 'distribution-select',
                        'value' => $currentDistribution,
                    ]) ?>
                </div>
                <div class="flex-fill<?= $currentDistribution === 4 ? '' : ' d-none' ?>" id="sg-container">
                    <?= $this->Form->select('sharing_group_id', $dropdownData['sgs'], [
                        'empty' => __('Select a sharing group…'),
                        'class' => 'form-select tom-select',
                        'default' => $data['sharing_group_id'] ?? null,
                    ]) ?>
                </div>
            </div>
        </div>

        <?php if ($m === 'Note'): ?>
            <!-- ── NOTE ────────────────────────────────────────── -->
            <div class="w-100 px-2">
                <div class="d-flex align-items-center gap-2 text-<?= $color ?> fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Note') ?>
                    <span class="badge bg-<?= $color ?>" style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <?= $this->Form->textarea('note', [
                    'class'       => 'form-control',
                    'rows'        => 4,
                    'placeholder' => __('Write your analysis note…'),
                ]) ?>
            </div>
            <div class="w-100 px-2">
                <div class="text-<?= $color ?> fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Language') ?>
                </div>
                <?= $this->Form->select('language', $languageOptions, [
                    'class' => 'form-select tom-select',
                    'default' => $data['language'] ?? '',
                ]) ?>
            </div>

        <?php elseif ($m === 'Opinion'): ?>
            <!-- ── OPINION ─────────────────────────────────────── -->
            <?php $opVal = isset($data['opinion']) ? (int)$data['opinion'] : 50; ?>
            <div class="w-100 px-2">
                <div class="d-flex align-items-center justify-content-between text-<?= $color ?> fw-bold text-uppercase mb-2"
                     style="letter-spacing:.1em;">
                    <span style="font-size:.65rem;"><?= __('Opinion') ?></span>
                    <span id="opinionLabel" class="badge" style="font-size:.65rem;"></span>
                </div>
                <input type="range" min="0" max="100" step="1" value="<?= $opVal ?>"
                       id="opinionRange" class="form-range">
                <?= $this->Form->text('opinion', ['id' => 'opinionValue', 'value' => $opVal, 'style' => 'display:none;']) ?>
                <div class="d-flex justify-content-between text-muted" style="font-size:.7rem;">
                    <span><?= __('Strongly disagree') ?></span>
                    <span><?= __('Neutral') ?></span>
                    <span><?= __('Strongly agree') ?></span>
                </div>
            </div>
            <div class="w-100 px-2">
                <div class="text-<?= $color ?> fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Comment') ?>
                </div>
                <?= $this->Form->textarea('comment', [
                    'class'       => 'form-control',
                    'rows'        => 3,
                    'placeholder' => __('Justify your opinion…'),
                ]) ?>
            </div>

        <?php elseif ($m === 'Relationship'): ?>
            <!-- ── RELATIONSHIP ────────────────────────────────── -->
            <div class="w-100 px-2">
                <div class="text-<?= $color ?> fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Relationship type') ?>
                </div>
                <?= $this->Form->text('relationship_type', [
                    'class'       => 'form-control',
                    'list'        => 'relationshipTypeList',
                    'placeholder' => __('e.g. related-to, derived-from…'),
                    'default'     => $data['relationship_type'] ?? null,
                ]) ?>
                <datalist id="relationshipTypeList">
                    <?php foreach (($existingRelations ?? []) as $rel): ?>
                        <option value="<?= h($rel) ?>"></option>
                    <?php endforeach; ?>
                </datalist>
            </div>
            <div class="w-100 px-2">
                <div class="text-<?= $color ?> fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Related object') ?>
                </div>
                <div class="d-flex gap-3 flex-wrap">
                    <div style="min-width:12rem;">
                        <?= $this->Form->select('related_object_type', $dropdownData['valid_targets'], [
                            'class'   => 'form-select tom-select',
                            'empty'   => __('Select type…'),
                            'id'      => 'relatedObjectType',
                            'default' => $data['related_object_type'] ?? null,
                        ]) ?>
                    </div>
                    <div class="flex-grow-1" style="min-width:18rem;">
                        <?= $this->Form->text('related_object_uuid', [
                            'class'       => 'form-control',
                            'id'          => 'relatedObjectUuid',
                            'placeholder' => 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX',
                            'default'     => $data['related_object_uuid'] ?? null,
                        ]) ?>
                    </div>
                </div>
                <div id="relatedObjectPreview" class="mt-2" style="display:none;"></div>
            </div>
        <?php endif; ?>

        <!-- ── AUTHORS ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-<?= $color ?> fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Authors') ?>
            </div>
            <?= $this->Form->text('authors', [
                'class'   => 'form-control',
                'default' => $data['authors'] ?? ($me['email'] ?? ''),
            ]) ?>
        </div>

    </div>

    <?php
    $footerMeta = [];
    if (!empty($me['email'])) {
        $footerMeta[] = ['label' => __('Analyst'), 'value' => $me['email']];
        if (!empty($me['Organisation']['name'])) {
            $footerMeta[] = ['label' => __('Org'), 'value' => $me['Organisation']['name']];
        }
    }
    echo $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => $color,
        'isEdit' => $isEdit,
        'meta' => $footerMeta,
        'submit' => ['label' => $isEdit ? __('Save changes') : __('Create %s', $s['label'])],
    ]);
    ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var base = <?= json_encode($baseurl, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    /* Opinion slider → hidden value + coloured live label */
    var range = document.getElementById('opinionRange');
    var hidden = document.getElementById('opinionValue');
    var label = document.getElementById('opinionLabel');
    if (range && hidden && label) {
        var refresh = function () {
            var v = parseInt(range.value, 10);
            hidden.value = v;
            var text, cls;
            if (v >= 81)      { text = <?= json_encode(__('Strongly Agree')) ?>;    cls = 'bg-success'; }
            else if (v >= 61) { text = <?= json_encode(__('Agree')) ?>;             cls = 'bg-success'; }
            else if (v >= 41) { text = <?= json_encode(__('Neutral')) ?>;           cls = 'bg-secondary'; }
            else if (v >= 21) { text = <?= json_encode(__('Disagree')) ?>;          cls = 'bg-danger'; }
            else              { text = <?= json_encode(__('Strongly Disagree')) ?>; cls = 'bg-danger'; }
            label.className = 'badge ' + cls;
            label.textContent = text + ' · ' + v + '/100';
        };
        range.addEventListener('input', refresh);
        refresh();
    }

    /* Relationship: preview the related object as the type/uuid are filled */
    var rType = document.getElementById('relatedObjectType');
    var rUuid = document.getElementById('relatedObjectUuid');
    var rPrev = document.getElementById('relatedObjectPreview');
    if (rUuid && rPrev) {
        var fetchPreview = function () {
            var type = rType ? rType.value : '';
            var uuid = (rUuid.value || '').trim();
            if (!type || uuid.length !== 36) { rPrev.style.display = 'none'; return; }
            fetch(base + '/analystData/getRelatedElement/' + encodeURIComponent(type) + '/' + encodeURIComponent(uuid),
                  { headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                    if (!d || Object.keys(d).length === 0) {
                        rPrev.innerHTML = '<div class="text-muted small"><i class="fas fa-circle-info me-1"></i>'
                            + <?= json_encode(__('No matching object found or preview unsupported.')) ?> + '</div>';
                    } else {
                        rPrev.innerHTML = '<pre class="border rounded p-2 bg-light small mb-0" style="max-height:180px; overflow:auto;">'
                            + JSON.stringify(d, null, 2).replace(/</g, '&lt;') + '</pre>';
                    }
                    rPrev.style.display = '';
                })
                .catch(function () { rPrev.style.display = 'none'; });
        };
        rUuid.addEventListener('input', fetchPreview);
        if (rType) { rType.addEventListener('change', fetchPreview); }
        fetchPreview();
    }
})();
</script>
