<?php
$isEdit = $this->request->params['action'] === 'edit';

$warninglist = $this->request->data['Warninglist'] ?? [];

$currentCategory = $warninglist['category'] ?? 'false_positive';
$currentType = $warninglist['type'] ?? 'string';

/* What each matching type does, shown in the picker instead of the bare
 * keyword the model validates against. */
$typeMeta = [
    'string' => [
        'label' => __('String'),
        'hint' => __('the value is exactly this entry'),
        'icon' => 'fas fa-equals',
    ],
    'substring' => [
        'label' => __('Substring'),
        'hint' => __('the value contains this entry'),
        'icon' => 'fas fa-quote-right',
    ],
    'hostname' => [
        'label' => __('Hostname'),
        'hint' => __('the host part of the value matches'),
        'icon' => 'fas fa-globe',
    ],
    'cidr' => [
        'label' => __('CIDR'),
        'hint' => __('the IP falls inside this range'),
        'icon' => 'fas fa-network-wired',
    ],
    'regex' => [
        'label' => __('Regular expression'),
        'hint' => __('the value matches this pattern'),
        'icon' => 'fas fa-asterisk',
    ],
];
$typeOptions = [];
foreach (($possibleTypes ?? []) as $value => $label) {
    $typeOptions[$value] = $typeMeta[$value]['label'] ?? $label;
}

$categoryMeta = [
    'false_positive' => [
        'icon' => 'fas fa-thumbs-down',
        'hint' => __('Hits are likely harmless noise'),
    ],
    'known' => [
        'icon' => 'fas fa-circle-check',
        'hint' => __('Hits are known, identified infrastructure'),
    ],
];

echo $this->Form->create('Warninglist', [
    'id' => 'warninglistForm',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:var(--warninglist-soft);
            border-bottom:2px solid var(--warninglist);">
    <div>
        <div class="text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;
                    color:var(--warninglist);">
            <?= __('Warning Lists') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?>"
               style="font-size:1.25rem; color:var(--warninglist);"></i>
            <?= $isEdit ? __('Edit Warninglist') : __('Add Warninglist') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('A warninglist flags attributes whose value it recognises, without changing them.') ?>
        </p>
    </div>
    <i class="fas fa-exclamation-triangle"
       style="font-size:2rem; opacity:.45; color:var(--warninglist);"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 fw-bold text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;
                            color:var(--warninglist);">
                    <?= __('Name') ?>
                    <span class="badge text-white"
                          style="font-size:.55rem; opacity:.8; font-weight:700;
                                 background:var(--warninglist);">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <span class="text-muted" id="warninglistNameCounter"
                      style="font-size:.7rem;">0/60</span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'WarninglistName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'maxlength' => 60,
                'placeholder' => __('e.g. Known public DNS resolvers'),
                'autocomplete' => 'off',
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Keep it short but descriptive — 60 characters at most.') ?>
            </div>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;
                        color:var(--warninglist);">
                <?= __('Description') ?>
                <span class="badge text-white"
                      style="font-size:.55rem; opacity:.8; font-weight:700;
                             background:var(--warninglist);">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->textarea('description', [
                'id' => 'WarninglistDescription',
                'class' => 'form-control',
                'rows' => 2,
                'style' => 'border-color:#d8dde3;',
                'placeholder' => __('What this list contains and why a hit matters…'),
            ]) ?>
        </div>

        <!-- ── CATEGORY ────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;
                        color:var(--warninglist);">
                <?= __('Category') ?>
            </div>
            <?= $this->Form->select('category', $possibleCategories ?? [], [
                'id' => 'WarninglistCategory',
                'value' => $currentCategory,
                'empty' => false,
                'style' => 'display:none;',
            ]) ?>
            <div class="row g-2">
                <?php foreach (($possibleCategories ?? []) as $value => $label):
                    $meta = $categoryMeta[$value] ?? ['icon' => 'fas fa-tag', 'hint' => ''];
                    $selected = ($value === $currentCategory);
                ?>
                    <div class="col-md-6 warninglist-category-card"
                         style="cursor:pointer;"
                         data-value="<?= h($value) ?>">
                        <div class="border rounded p-3 h-100 d-flex align-items-center gap-3"
                             style="transition:border-color .15s, background .15s;
                                    <?= $selected
                                        ? 'border-color:var(--warninglist) !important;'
                                            . ' background:var(--warninglist-soft);'
                                        : 'border-color:#d8dde3;' ?>">
                            <i class="<?= h($meta['icon']) ?>"
                               style="font-size:1rem; color:var(--warninglist);
                                      opacity:<?= $selected ? '1' : '.45' ?>;"></i>
                            <div>
                                <div class="fw-bold" style="font-size:.85rem; line-height:1.2;">
                                    <?= h($label) ?>
                                </div>
                                <div class="text-muted" style="font-size:.72rem; line-height:1.3;">
                                    <?= h($meta['hint']) ?>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <!-- ── TYPE / MATCHING ATTRIBUTES ──────────────────────── -->
        <div class="row g-3">

            <div class="col-md-5 px-2">
                <div class="fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;
                            color:var(--warninglist);">
                    <?= __('Matching Type') ?>
                </div>
                <?= $this->Form->select('type', $typeOptions, [
                    'id' => 'warninglist-type-select',
                    'class' => 'form-select',
                    'value' => $currentType,
                    'empty' => false,
                ]) ?>
                <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                     style="font-size:.75rem;">
                    <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                    <?= __('How an entry below is compared to an attribute value.') ?>
                </div>
            </div>

            <div class="col-md-7 px-2">
                <div class="fw-bold text-uppercase mb-2"
                     style="font-size:.65rem; letter-spacing:.1em;
                            color:var(--warninglist);">
                    <?= __('Accepted Attribute Types') ?>
                </div>
                <?= $this->Form->select('matching_attributes', $matchingAttributes ?? [], [
                    'id' => 'WarninglistMatchingAttributes',
                    'multiple' => true,
                    'class' => 'form-select tom-select',
                    'data-placeholder' => __('Every attribute type'),
                ]) ?>
                <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                     style="font-size:.75rem;">
                    <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                    <?= __('Left empty, the list is checked against every attribute type.') ?>
                </div>
            </div>

        </div>

        <!-- ── VALUES ──────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 fw-bold text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;
                            color:var(--warninglist);">
                    <?= __('Values') ?>
                    <span class="badge text-white"
                          style="font-size:.55rem; opacity:.8; font-weight:700;
                                 background:var(--warninglist);">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <span class="text-muted" id="warninglistEntryCounter"
                      style="font-size:.7rem;"></span>
            </div>
            <?= $this->Form->textarea('entries', [
                'id' => 'WarninglistEntries',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.875rem; min-height:200px;'
                    . ' color:inherit; font-family:monospace;',
                'rows' => 8,
                'placeholder' => "8.8.8.8\n1.1.1.1 # Cloudflare resolver",
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('One value per line. Anything after a # is kept as that entry\'s comment.') ?>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($warninglist['id'])): ?>
                <?= __('Warninglist') ?>:
                <strong class="text-body">#<?= h($warninglist['id']) ?></strong>
                <?php if (isset($warninglist['version'])): ?>
                    &nbsp;|&nbsp; <?= __('Version') ?>:
                    <strong class="text-body"><?= h($warninglist['version']) ?></strong>
                    <?= __('(bumped on save)') ?>
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
                    . ($isEdit ? __('Save Changes') : __('Add Warninglist')),
                [
                    'class' => 'btn btn-sm text-white',
                    'style' => 'background:var(--warninglist);'
                        . ' border-color:var(--warninglist);',
                    'escapeTitle' => false,
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var TYPE_META = <?= json_encode($typeMeta, JSON_FORCE_OBJECT
        | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var L_ENTRIES = <?= json_encode(__('%s value(s)')) ?>;
    var REQUIRED = {
        WarninglistName: <?= json_encode(__('Please provide a name for the warninglist.')) ?>,
        WarninglistDescription: <?= json_encode(__('Please describe what this warninglist covers.')) ?>,
        WarninglistEntries: <?= json_encode(__('Please provide at least one value.')) ?>
    };

    /* Matching type — the badge shape the other pickers use, in the
       warninglist rose, with the behaviour spelled out in the dropdown. */
    function renderType(data, escape, compact) {
        var meta = TYPE_META[data.value]
            || { icon: 'fas fa-question', hint: '' };
        var html = '<div class="d-flex align-items-center gap-2' + (compact ? '' : ' py-1') + '">'
            + '<span class="badge d-inline-flex align-items-center'
                + (compact ? ' px-1' : ' px-2 py-1') + '" style="'
                + 'background:var(--warninglist-soft); color:var(--warninglist);'
                + 'border:1px solid var(--warninglist-soft);'
                + (compact ? 'font-size:.65rem;' : '') + '">'
            + '<i class="' + meta.icon + '"></i>'
            + '</span>'
            + '<span>' + escape(data.text) + '</span>';
        if (!compact && meta.hint) {
            html += '<span class="text-muted ms-auto ps-2" style="font-size:.72rem;">'
                + escape(meta.hint) + '</span>';
        }
        return html + '</div>';
    }

    var typeEl = document.getElementById('warninglist-type-select');
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

    /* Category cards drive the hidden select */
    var categoryEl = document.getElementById('WarninglistCategory');
    var cards = document.querySelectorAll('.warninglist-category-card');
    cards.forEach(function (card) {
        card.addEventListener('click', function () {
            cards.forEach(function (other) {
                var box = other.querySelector('div');
                var icon = other.querySelector('i');
                var on = (other === card);
                box.style.borderColor = on ? 'var(--warninglist)' : '#d8dde3';
                box.style.background = on ? 'var(--warninglist-soft)' : '';
                if (icon) { icon.style.opacity = on ? '1' : '.45'; }
            });
            if (categoryEl) { categoryEl.value = card.dataset.value; }
        });
    });

    /* Live counters */
    var nameEl = document.getElementById('WarninglistName');
    var nameCounter = document.getElementById('warninglistNameCounter');
    if (nameEl && nameCounter) {
        var refreshName = function () {
            nameCounter.textContent = nameEl.value.length + '/60';
        };
        nameEl.addEventListener('input', refreshName);
        refreshName();
    }

    var entriesEl = document.getElementById('WarninglistEntries');
    var entryCounter = document.getElementById('warninglistEntryCounter');
    if (entriesEl && entryCounter) {
        var refreshEntries = function () {
            var count = entriesEl.value.split('\n').filter(function (line) {
                return line.trim() !== '';
            }).length;
            entryCounter.textContent = L_ENTRIES.replace('%s', count);
        };
        entriesEl.addEventListener('input', refreshEntries);
        refreshEntries();
    }

    /* The three fields the model refuses to save empty */
    var form = document.getElementById('warninglistForm');
    if (form) {
        function fieldError(el, show, message) {
            var errorId = el.id + 'Error';
            var existing = document.getElementById(errorId);
            var underlined = el.tagName === 'INPUT';
            if (!show) {
                if (underlined) {
                    el.style.setProperty('border-bottom-color', '#d8dde3', 'important');
                } else {
                    el.style.setProperty('border-color', '#d8dde3', 'important');
                }
                if (existing) { existing.remove(); }
                return;
            }
            if (underlined) {
                el.style.setProperty('border-bottom-color', '#dc3545', 'important');
            } else {
                el.style.setProperty('border-color', '#dc3545', 'important');
            }
            if (existing) { return; }
            var msg = document.createElement('div');
            msg.id = errorId;
            msg.className = 'text-danger d-flex align-items-center gap-1';
            msg.style.fontSize = '.75rem';
            msg.style.marginTop = '.35rem';
            var icon = document.createElement('i');
            icon.className = 'fas fa-circle-exclamation';
            msg.appendChild(icon);
            msg.appendChild(document.createTextNode(message));
            el.parentNode.insertBefore(msg, el.nextSibling);
        }

        var required = Object.keys(REQUIRED).map(function (id) {
            return document.getElementById(id);
        }).filter(Boolean);

        form.addEventListener('submit', function (e) {
            var firstEmpty = null;
            required.forEach(function (el) {
                var empty = !el.value.trim();
                fieldError(el, empty, REQUIRED[el.id]);
                if (empty && !firstEmpty) { firstEmpty = el; }
            });
            if (firstEmpty) {
                e.preventDefault();
                e.stopPropagation();
                firstEmpty.focus();
            }
        });

        required.forEach(function (el) {
            el.addEventListener('input', function () {
                if (el.value.trim()) { fieldError(el, false); }
            });
        });
    }
})();
</script>
