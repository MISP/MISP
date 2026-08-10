<?php
$isEdit = $this->request->params['action'] === 'edit';

$data = $this->request->data['Collection'] ?? [];

/* edit() does not set initialDistribution — fall back to the stored value */
$currentDistribution = isset($data['distribution'])
    ? (int)$data['distribution']
    : (int)($initialDistribution ?? 0);

$types = $dropdownData['types'] ?? [];
$typeIcons = [
    'campaign'      => 'fas fa-bullseye',
    'intrusion_set' => 'fas fa-user-secret',
    'named_threat'  => 'fas fa-skull-crossbones',
    'research'      => 'fas fa-flask',
    'other'         => 'fas fa-shapes',
];
$typeOptions = [];
foreach ($types as $value => $label) {
    $typeOptions[$value] = ucfirst(str_replace('_', ' ', (string)$label));
}


$attachElementUuids = !empty($attachElementUuids)
    ? array_values(array_filter((array)$attachElementUuids))
    : (!empty($attachElementUuid) ? [$attachElementUuid] : []);
$hasAttachTarget = !empty($attachElementType) && !empty($attachElementUuids);

echo $this->Form->create('Collection', [
    'id' => 'collectionForm',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Collections') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Collection') : __('Add Collection') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Organise shared data into buckets based on commonalities or as part of your research process. Collections follow the same sharing rules as events do.') ?>
        </p>
    </div>
    <i class="fas fa-folder-open text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>


<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <?php if ($hasAttachTarget): ?>
            <!-- ── ATTACH TARGET ───────────────────────────────── -->
            <div class="alert alert-light border d-flex align-items-center gap-3 mb-0"
                 role="alert" style="border-color:var(--primary) !important;">
                <i class="fas fa-link text-primary"></i>
                <div class="flex-grow-1">
                    <div class="fw-semibold" style="font-size:.85rem;">
                        <?= __('%s element(s) will be attached', count($attachElementUuids)) ?>
                    </div>
                    <div class="text-muted" style="font-size:.75rem; margin-top:.15rem;">
                        <?= h($attachElementType) ?> ·
                        <code><?= h(implode(', ', $attachElementUuids)) ?></code>
                    </div>
                </div>
            </div>
            <?php
            echo $this->Form->hidden('_attach_element_type', [
                'value' => $attachElementType,
            ]);
            foreach ($attachElementUuids as $i => $attachElementUuidValue) {
                echo $this->Form->hidden('Collection._attach_element_uuid.' . $i, [
                    'value' => $attachElementUuidValue,
                ]);
            }
            ?>
        <?php endif; ?>

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 text-primary fw-bold
                            text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Collection Name') ?>
                    <span class="badge bg-primary"
                          style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <span class="text-muted" id="collectionNameCounter"
                      style="font-size:.7rem;">0/60</span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'CollectionName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'maxlength' => 60,
                'placeholder' => __('e.g. APTX phishing campaign assets'),
                'autocomplete' => 'off',
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Keep it short but descriptive — 60 characters at most.') ?>
            </div>
        </div>

        <!-- ── TYPE ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Collection Type') ?>
            </div>
            <?= $this->Form->select('type', $typeOptions, [
                'id' => 'collection-type-select',
                'class' => 'form-select',
                'empty' => __('Select a type…'),
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('What the collection groups together — a campaign, an intrusion set, a named threat, or your own research.') ?>
            </div>
        </div>

        <!-- ── DISTRIBUTION / SHARING GROUP ───────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Distribution / Sharing Group') ?>
            </div>
            <div class="d-flex gap-3">

                <div class="flex-fill">
                    <?= $this->Form->select('distribution', $dropdownData['distributionLevels'] ?? [], [
                        'class' => 'form-select',
                        'id' => 'distribution-select',
                        'value' => $currentDistribution,
                    ]) ?>
                </div>

                <div class="flex-fill<?= $currentDistribution === 4 ? '' : ' d-none' ?>"
                     id="sg-container">
                    <?= $this->Form->select('sharing_group_id', $dropdownData['sgs'] ?? [], [
                        'id' => 'sharing-group-select',
                        'empty' => __('Select a sharing group…'),
                        'class' => 'form-select tom-select',
                    ]) ?>
                </div>

            </div>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-primary fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Description') ?>
            </div>
            <?= $this->Form->textarea('description', [
                'class' => 'form-control',
                'rows' => 3,
                'style' => 'border-color:#d8dde3;',
                'placeholder' => __('Briefly describe what this collection is for and what kind of assets it contains…'),
            ]) ?>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($id)): ?>
                <?= __('Collection') ?>:
                <strong class="text-body">#<?= h($id) ?></strong>
            <?php elseif (!empty($me['email'])): ?>
                <?= __('Analyst') ?>:
                <strong class="text-body"><?= h($me['email']) ?></strong>
                <?php if (!empty($me['Organisation']['name'])): ?>
                    &nbsp;|&nbsp; <?= __('Org') ?>:
                    <strong class="text-body"><?= h($me['Organisation']['name']) ?></strong>
                <?php endif; ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Create Collection')),
                [
                    'class' => 'btn btn-primary btn-sm',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var TYPE_ICONS = <?= json_encode($typeIcons, JSON_FORCE_OBJECT
        | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var NAME_REQUIRED = <?= json_encode(__('Please provide a name for the collection.')) ?>;

    function renderType(data, escape, compact) {
        if (!data.value) {
            return '<div class="text-muted py-1">' + escape(data.text) + '</div>';
        }
        var icon = TYPE_ICONS[data.value] || 'fas fa-folder';
        return '<div class="d-flex align-items-center gap-2' + (compact ? '' : ' py-1') + '">'
            + '<span class="badge d-inline-flex align-items-center'
                + (compact ? ' px-1' : ' px-2 py-1') + '" style="'
                + 'background:rgba(24,146,177,.12); color:var(--primary);'
                + 'border:1px solid rgba(24,146,177,.25);'
                + (compact ? 'font-size:.65rem;' : '') + '">'
            + '<i class="' + icon + '"></i>'
            + '</span>'
            + '<span>' + escape(data.text) + '</span>'
            + '</div>';
    }

    var typeEl = document.getElementById('collection-type-select');
    if (typeEl && !typeEl.tomselect && typeof TomSelect !== 'undefined') {
        new TomSelect(typeEl, {
            create: false,
            persist: false,
            render: {
                option: function (data, escape) { return renderType(data, escape, false); },
                item: function (data, escape) { return renderType(data, escape, true); }
            }
        });
    }


    if (typeof initDistributionSelect === 'function') {
        initDistributionSelect('distribution-select', function (value) {
            var sg = document.getElementById('sg-container');
            if (sg) { sg.classList.toggle('d-none', parseInt(value, 10) !== 4); }
        });
    }

    /* Live character counter on the name */
    var nameEl = document.getElementById('CollectionName');
    var counterEl = document.getElementById('collectionNameCounter');
    if (nameEl && counterEl) {
        var refreshCounter = function () {
            counterEl.textContent = nameEl.value.length + '/60';
        };
        nameEl.addEventListener('input', refreshCounter);
        refreshCounter();
    }

    /* Block the submit only when the name is actually empty */
    var form = document.getElementById('collectionForm');
    if (form && nameEl) {
        var errorId = 'collectionNameError';

        var showError = function () {
            nameEl.style.setProperty('border-bottom-color', '#dc3545', 'important');
            if (!document.getElementById(errorId)) {
                var msg = document.createElement('div');
                msg.id = errorId;
                msg.className = 'text-danger d-flex align-items-center gap-1';
                msg.style.fontSize = '.75rem';
                msg.style.marginTop = '.35rem';
                var icon = document.createElement('i');
                icon.className = 'fas fa-circle-exclamation';
                msg.appendChild(icon);
                msg.appendChild(document.createTextNode(NAME_REQUIRED));
                nameEl.parentNode.insertBefore(msg, nameEl.nextSibling);
            }
        };

        var clearError = function () {
            nameEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
            var msg = document.getElementById(errorId);
            if (msg) { msg.remove(); }
        };

        form.addEventListener('submit', function (e) {
            if (!nameEl.value.trim()) {
                e.preventDefault();
                e.stopPropagation();
                showError();
                nameEl.focus();
            }
        });

        nameEl.addEventListener('input', function () {
            if (nameEl.value.trim()) { clearError(); }
        });
    }
})();
</script>
