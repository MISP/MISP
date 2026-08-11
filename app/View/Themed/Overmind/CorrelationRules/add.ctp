<?php
$isEdit = $this->request->params['action'] === 'edit';

$rule = $this->request->data['CorrelationRule'] ?? [];
$currentType = $rule['selector_type'] ?? 'event_id';

/* Stored as a JSON array and handed back decoded by
 * CorrelationRule::afterFind(); the editor wants it as pretty JSON. */
$selectorList = $rule['selector_list'] ?? '';
if (is_array($selectorList)) {
    $selectorList = json_encode($selectorList, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

/* How each selector type reads its list, straight from what
 * CorrelationRule::generateVirtualTable() does with the values. */
$typeMeta = [
    'orgc_id' => [
        'icon' => 'fas fa-building',
        'hint' => __('Organisation ids — every event created by them is excluded.'),
        'placeholder' => "[\n    12,\n    47\n]",
        'numeric' => true,
    ],
    'org_id' => [
        'icon' => 'fas fa-users',
        'hint' => __('Organisation ids — every event owned locally by them is excluded.'),
        'placeholder' => "[\n    12,\n    47\n]",
        'numeric' => true,
    ],
    'event_id' => [
        'icon' => 'misp-icon misp-icon-event misp-simple',
        'hint' => __('Event ids — those events alone are excluded.'),
        'placeholder' => "[\n    1454,\n    1455\n]",
        'numeric' => true,
    ],
    'event_info' => [
        'icon' => 'fas fa-align-left',
        'hint' => __('Patterns matched against the event info with SQL LIKE — put your own % wildcards in.'),
        'placeholder' => "[\n    \"%daily ingestion%\",\n    \"%botnet feed%\"\n]",
        'numeric' => false,
    ],
];

$selectorTypes = $dropdownData['selector_types'] ?? [];

echo $this->Form->create('CorrelationRule', [
    'id' => 'correlationRuleForm',
    'novalidate' => true,
]);
?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(177, 106, 24, 0.06);
            border-bottom:2px solid var(--correlation);">
    <div>
        <div class="text-correlation text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Correlation Rules') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-correlation"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Correlation Rule') : __('Add Correlation Rule') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Stops correlations from being built between the events a rule selects — the cure for a feed that over-correlates on every ingestion.') ?>
        </p>
    </div>
    <i class="fas fa-link text-correlation" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-correlation fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Rule Name') ?>
                <span class="badge bg-correlation"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'CorrelationRuleName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #e3dfd8 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. Skip the daily OSINT ingestion'),
                'autocomplete' => 'off',
            ]) ?>
        </div>

        <!-- ── SELECTOR TYPE ───────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-correlation fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Selector Type') ?>
            </div>
            <?= $this->Form->select('selector_type', $selectorTypes, [
                'id' => 'correlation-rule-type-select',
                'class' => 'form-select',
                'value' => $currentType,
                'empty' => false,
            ]) ?>
            <div class="d-flex align-items-start gap-1 mt-1 text-muted"
                 id="CorrelationRuleTypeHint" style="font-size:.75rem;"></div>
        </div>

        <!-- ── SELECTOR LIST ───────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 text-correlation fw-bold
                            text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Selectors') ?>
                    <span class="badge bg-correlation"
                          style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <span id="correlationRuleStatus" class="badge bg-secondary"
                          style="font-size:.65rem;"></span>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            id="correlationRuleFormatBtn"
                            style="font-size:.7rem; padding:.15rem .5rem;">
                        <i class="fas fa-wand-magic-sparkles me-1"></i><?= __('Format') ?>
                    </button>
                </div>
            </div>

            <?= $this->Form->textarea('selector_list', [
                'id' => 'CorrelationRuleSelectorList',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #faf9f8);'
                    . ' border:1px solid #e3dfd8; resize:vertical;'
                    . ' outline:none; font-size:.85rem; min-height:160px;'
                    . ' color:inherit; font-family:monospace;'
                    . ' white-space:pre; overflow-x:auto;',
                'rows' => 8,
                'spellcheck' => 'false',
                'value' => $selectorList,
            ]) ?>
            <div id="correlationRuleError" class="d-none text-danger
                        d-flex align-items-start gap-1 mt-1"
                 style="font-size:.75rem;"></div>

            <!-- Reading of the list, rebuilt as it is typed -->
            <div class="mt-2 d-none" id="correlationRuleReadingWrap">
                <div class="border rounded p-2" id="correlationRuleReading"
                     style="border-color:#d8dde3 !important; font-size:.78rem;
                            max-height:160px; overflow-y:auto;"></div>
            </div>

            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('A JSON array — an empty list is refused on save.') ?>
            </div>
        </div>

        <!-- ── COMMENT ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="text-correlation fw-bold text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Comment') ?>
            </div>
            <?= $this->Form->textarea('comment', [
                'class' => 'form-control',
                'rows' => 2,
                'style' => 'border-color:#d8dde3;',
                'placeholder' => __('Why these events should not correlate…'),
            ]) ?>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($id)): ?>
                <?= __('Rule') ?>:
                <strong class="text-body">#<?= h($id) ?></strong>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Existing correlations stay until the rule is executed from the index.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Rule')),
                [
                    'class' => 'btn btn-correlation btn-sm',
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
    var L = {
        nameRequired: <?= json_encode(__('Please provide a name for the rule.')) ?>,
        empty: <?= json_encode(__('No selector')) ?>,
        invalid: <?= json_encode(__('Invalid JSON')) ?>,
        arrayExpected: <?= json_encode(__('The selectors have to be a JSON array, e.g. [1, 2].')) ?>,
        emptyRefused: <?= json_encode(__('At least one selector is needed — the model refuses an empty list.')) ?>,
        numericExpected: <?= json_encode(__('This type selects on ids, so every entry has to be a number — %s is not.')) ?>,
        blankEntry: <?= json_encode(__('Entry %s is empty.')) ?>,
        count: <?= json_encode(__('%s selector(s)')) ?>,
        noWildcard: <?= json_encode(__('Without a %% wildcard, %s only matches an event whose info is exactly that.')) ?>
    };

    function el(id) { return document.getElementById(id); }

    var typeEl = el('correlation-rule-type-select');
    var hintEl = el('CorrelationRuleTypeHint');
    var listEl = el('CorrelationRuleSelectorList');
    var statusEl = el('correlationRuleStatus');
    var errorEl = el('correlationRuleError');
    var readingEl = el('correlationRuleReading');
    var readingWrap = el('correlationRuleReadingWrap');
    var nameEl = el('CorrelationRuleName');
    var form = el('correlationRuleForm');

    function meta() {
        return TYPE_META[typeEl ? typeEl.value : ''] || null;
    }

    /* Selector type — the badge shape the other pickers use */
    function renderType(data, escape, compact) {
        var m = TYPE_META[data.value] || { icon: 'fas fa-question', hint: '' };
        var html = '<div class="d-flex align-items-center gap-2' + (compact ? '' : ' py-1') + '">'
            + '<span class="badge d-inline-flex align-items-center'
                + (compact ? ' px-1' : ' px-2 py-1') + '" style="'
                + 'background:rgba(24,146,177,.12); color:var(--correlation);'
                + 'border:1px solid rgba(24,146,177,.25);'
                + (compact ? 'font-size:.65rem;' : '') + '">'
            + '<i class="' + m.icon + '"></i>'
            + '</span>'
            + '<span>' + escape(data.text) + '</span>'
            + '</div>';
        return html;
    }

    if (typeEl && !typeEl.tomselect && typeof TomSelect !== 'undefined') {
        new TomSelect(typeEl, {
            create: false,
            persist: false,
            render: {
                option: function (data, escape) { return renderType(data, escape, false); },
                item: function (data, escape) { return renderType(data, escape, true); }
            },
            onChange: function () { refreshType(); }
        });
    } else if (typeEl) {
        typeEl.addEventListener('change', refreshType);
    }

    /* The list means something different per type — say what, and adapt the
     * placeholder so the expected shape is visible before typing. */
    function refreshType() {
        var m = meta();
        if (hintEl) {
            hintEl.innerHTML = '';
            if (m) {
                var icon = document.createElement('i');
                icon.className = m.icon;
                icon.style.fontSize = '.7rem';
                icon.style.marginTop = '.15rem';
                hintEl.appendChild(icon);
                hintEl.appendChild(document.createTextNode(m.hint));
            }
        }
        if (listEl && m) { listEl.setAttribute('placeholder', m.placeholder); }
        refreshList();
    }

    function setStatus(kind, text) {
        if (!statusEl) { return; }
        statusEl.className = 'badge bg-' + kind;
        statusEl.style.fontSize = '.65rem';
        statusEl.textContent = text;
    }

    function setError(message) {
        if (!errorEl) { return; }
        if (!message) {
            errorEl.classList.add('d-none');
            errorEl.textContent = '';
            return;
        }
        errorEl.classList.remove('d-none');
        errorEl.innerHTML = '';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        icon.style.marginTop = '.15rem';
        errorEl.appendChild(icon);
        errorEl.appendChild(document.createTextNode(message));
    }

    function findProblem(list) {
        var m = meta();
        if (!list.length) { return L.emptyRefused; }
        for (var i = 0; i < list.length; i++) {
            var value = list[i];
            if (value === null || value === '' ) {
                return L.blankEntry.replace('%s', '#' + (i + 1));
            }
            if (m && m.numeric && isNaN(Number(value))) {
                return L.numericExpected.replace('%s', '"' + value + '"');
            }
        }
        return null;
    }

    function buildReading(list) {
        var m = meta();
        var wrap = document.createDocumentFragment();
        var row = document.createElement('div');
        row.className = 'd-flex flex-wrap gap-1';
        list.forEach(function (value) {
            var badge = document.createElement('span');
            badge.className = 'badge text-bg-light border font-monospace';
            badge.style.fontSize = '.68rem';
            badge.textContent = String(value);
            row.appendChild(badge);
        });
        wrap.appendChild(row);
        /* event_info goes through LIKE, so a pattern without % is exact */
        if (m && !m.numeric) {
            var literal = list.filter(function (value) {
                return String(value).indexOf('%') === -1;
            });
            if (literal.length) {
                var note = document.createElement('div');
                note.className = 'text-warning-emphasis mt-2';
                note.style.fontSize = '.72rem';
                note.textContent = L.noWildcard.replace('%s',
                    '"' + literal.join('", "') + '"');
                wrap.appendChild(note);
            }
        }
        return wrap;
    }

    function refreshList() {
        if (!listEl) { return; }
        var raw = listEl.value.trim();
        if (readingWrap) { readingWrap.classList.add('d-none'); }
        if (!raw) {
            setStatus('secondary', L.empty);
            setError(null);
            return;
        }
        var parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            setStatus('danger', L.invalid);
            setError(e.message);
            return;
        }
        if (!Array.isArray(parsed)) {
            setStatus('danger', L.invalid);
            setError(L.arrayExpected);
            return;
        }
        var problem = findProblem(parsed);
        setStatus(problem ? 'warning' : 'success',
            problem ? L.invalid : L.count.replace('%s', parsed.length));
        setError(problem);

        if (parsed.length && readingEl && readingWrap) {
            readingEl.innerHTML = '';
            readingEl.appendChild(buildReading(parsed));
            readingWrap.classList.remove('d-none');
        }
    }

    if (listEl) { listEl.addEventListener('input', refreshList); }

    var fmtBtn = el('correlationRuleFormatBtn');
    if (fmtBtn) {
        fmtBtn.addEventListener('click', function () {
            try {
                listEl.value = JSON.stringify(JSON.parse(listEl.value), null, 4);
            } catch (e) { /* refreshList() reports it */ }
            refreshList();
        });
    }

    if (form) {
        form.addEventListener('submit', function (e) {
            var noName = nameEl && !nameEl.value.trim();
            var noList = !listEl.value.trim();
            if (noName) {
                nameEl.style.setProperty('border-bottom-color', '#dc3545', 'important');
                if (!el('CorrelationRuleNameError')) {
                    var msg = document.createElement('div');
                    msg.id = 'CorrelationRuleNameError';
                    msg.className = 'text-danger d-flex align-items-center gap-1';
                    msg.style.fontSize = '.75rem';
                    msg.style.marginTop = '.35rem';
                    var icon = document.createElement('i');
                    icon.className = 'fas fa-circle-exclamation';
                    msg.appendChild(icon);
                    msg.appendChild(document.createTextNode(L.nameRequired));
                    nameEl.parentNode.insertBefore(msg, nameEl.nextSibling);
                }
            }
            if (noList) {
                setStatus('danger', L.invalid);
                setError(L.emptyRefused);
            }
            if (noName || noList) {
                e.preventDefault();
                e.stopPropagation();
                (noName ? nameEl : listEl).focus();
            }
        });

        if (nameEl) {
            nameEl.addEventListener('input', function () {
                if (!nameEl.value.trim()) { return; }
                nameEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
                var msg = el('CorrelationRuleNameError');
                if (msg) { msg.remove(); }
            });
        }
    }

    refreshType();
})();
</script>