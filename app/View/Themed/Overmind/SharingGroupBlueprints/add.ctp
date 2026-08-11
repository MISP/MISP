<?php
$isEdit = $this->request->params['action'] === 'edit';

$blueprint = $this->request->data['SharingGroupBlueprint'] ?? [];

/* Stored minified; the editor is much easier to read pretty-printed. An
 * unparseable value is shown untouched so it can be repaired by hand. */
$currentRules = $blueprint['rules'] ?? '';
if ($currentRules !== '') {
    $decoded = json_decode($currentRules);
    if ($decoded !== null) {
        $currentRules = json_encode($decoded, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }
}

/* What each filter narrows down on, keyed by the name used in the rules. The
 * keys themselves come from the model (see __setRuleVocabulary). */
$filterHints = [
    'org_id' => __('Organisation id'),
    'org_uuid' => __('Organisation UUID'),
    'org_name' => __('Organisation name'),
    'org_nationality' => __('Country the organisation belongs to'),
    'org_sector' => __('Sector the organisation works in'),
    'org_type' => __('Organisation type'),
    'sharing_group_id' => __('Members of a sharing group, by id'),
    'sharing_group_uuid' => __('Members of a sharing group, by UUID'),
];

$filterNames = [];
foreach (($validFilters ?? []) as $group) {
    foreach (array_keys($group) as $filter) {
        $filterNames[] = $filter;
    }
}
$operandList = $operands ?? ['OR', 'AND', 'NOT'];

echo $this->Form->create('SharingGroupBlueprint', [
    'id' => 'blueprintForm',
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
            <?= __('Sharing Group Blueprints') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-<?= $isEdit ? 'pen-to-square' : 'circle-plus' ?> text-primary"
               style="font-size:1.25rem;"></i>
            <?= $isEdit ? __('Edit Blueprint') : __('Add Blueprint') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('A rule over organisations, evaluated on demand to build and keep a sharing group up to date.') ?>
        </p>
    </div>
    <i class="fas fa-sitemap text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── NAME ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center gap-2 text-primary fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Blueprint Name') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('name', [
                'id' => 'BlueprintName',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1',
                'style' => 'border-bottom:1px solid #d8dde3 !important;'
                    . ' outline:none;',
                'placeholder' => __('e.g. European financial institutions'),
                'autocomplete' => 'off',
            ]) ?>
            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Also used as the name of the sharing group the blueprint creates.') ?>
            </div>
        </div>

        <!-- ── RULES ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 text-primary fw-bold
                            text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Rules') ?>
                    <span class="badge bg-primary"
                          style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <span id="blueprintRulesStatus" class="badge bg-secondary"
                          style="font-size:.65rem;"><?= __('Waiting for input') ?></span>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            id="blueprintFormatBtn"
                            style="font-size:.7rem; padding:.15rem .5rem;">
                        <i class="fas fa-wand-magic-sparkles me-1"></i><?= __('Format') ?>
                    </button>
                </div>
            </div>

            <!-- Palette: click to insert at the caret -->
            <div class="d-flex flex-wrap align-items-center gap-1 mb-2">
                <span class="text-muted text-uppercase fw-bold me-1"
                      style="font-size:.6rem; letter-spacing:.08em;">
                    <?= __('Operators') ?>
                </span>
                <?php foreach ($operandList as $operand): ?>
                    <button type="button"
                            class="btn btn-outline-primary btn-sm font-monospace blueprint-insert"
                            data-insert-operand="<?= h($operand) ?>"
                            style="font-size:.7rem; padding:.1rem .45rem;">
                        <?= h($operand) ?>
                    </button>
                <?php endforeach; ?>
            </div>
            <div class="d-flex flex-wrap align-items-center gap-1 mb-2">
                <span class="text-muted text-uppercase fw-bold me-1"
                      style="font-size:.6rem; letter-spacing:.08em;">
                    <?= __('Filters') ?>
                </span>
                <?php foreach ($filterNames as $filter): ?>
                    <button type="button"
                            class="btn btn-outline-secondary btn-sm font-monospace blueprint-insert"
                            data-insert-filter="<?= h($filter) ?>"
                            title="<?= h($filterHints[$filter] ?? $filter) ?>"
                            style="font-size:.7rem; padding:.1rem .45rem;">
                        <?= h($filter) ?>
                    </button>
                <?php endforeach; ?>
            </div>

            <?= $this->Form->textarea('rules', [
                'id' => 'SharingGroupBlueprintRules',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.875rem; min-height:240px;'
                    . ' color:inherit; font-family:monospace;'
                    . ' white-space:pre; overflow-x:auto;',
                'rows' => 14,
                'spellcheck' => 'false',
                'value' => $currentRules,
                'placeholder' => "{\n    \"AND\": {\n        \"org_sector\": \"Financial\",\n        \"org_nationality\": [\"FR\", \"BE\"]\n    }\n}",
            ]) ?>
            <div id="blueprintRulesError" class="d-none text-danger
                        d-flex align-items-center gap-1 mt-1"
                 style="font-size:.75rem;"></div>

            <!-- Reading of the rule as the model will walk it -->
            <div class="mt-3 d-none" id="blueprintTreeWrap">
                <div class="text-muted text-uppercase fw-bold mb-2"
                     style="font-size:.6rem; letter-spacing:.08em;">
                    <?= __('How this rule reads') ?>
                </div>
                <div class="border rounded p-3" id="blueprintTree"
                     style="border-color:#d8dde3 !important; font-size:.8rem;"></div>
            </div>

            <div class="d-flex align-items-start gap-2 rounded-2 p-2 mt-3 small"
                 style="background:rgba(24,146,177,.05);
                        border:1px solid rgba(24,146,177,.25);">
                <i class="fas fa-circle-info text-primary mt-1"
                   style="font-size:.7rem;"></i>
                <div class="text-muted">
                    <?= __('Nest %s, %s and %s branches to combine filters — a value can be a single value or a list.', '<code>OR</code>', '<code>AND</code>', '<code>NOT</code>') ?>
                    <?= __('The top level is evaluated as %s, and a %s branch cannot hold another branch.', '<code>OR</code>', '<code>NOT</code>') ?>
                </div>
            </div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;">
            <?php if ($isEdit && !empty($id)): ?>
                <?= __('Blueprint') ?>:
                <strong class="text-body">#<?= h($id) ?></strong>
            <?php else: ?>
                <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
                <?= __('Nothing is created until the blueprint is executed from the index.') ?>
            <?php endif; ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-' . ($isEdit ? 'floppy-disk' : 'circle-plus') . ' me-1"></i> '
                    . ($isEdit ? __('Save Changes') : __('Add Blueprint')),
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
    var FILTERS = <?= json_encode($filterNames, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var OPERANDS = <?= json_encode($operandList, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var HINTS = <?= json_encode($filterHints, JSON_FORCE_OBJECT | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var L = {
        waiting: <?= json_encode(__('Waiting for input')) ?>,
        valid: <?= json_encode(__('Valid')) ?>,
        invalid: <?= json_encode(__('Invalid JSON')) ?>,
        unknown: <?= json_encode(__('Unknown key')) ?>,
        nameRequired: <?= json_encode(__('Please provide a name for the blueprint.')) ?>,
        rulesRequired: <?= json_encode(__('Please provide the rules of the blueprint.')) ?>,
        notNested: <?= json_encode(__('A NOT branch cannot hold another branch — the model refuses it.')) ?>,
        unknownKey: <?= json_encode(__('"%s" is neither an operator nor a known filter, so it would match nothing.')) ?>,
        objectExpected: <?= json_encode(__('The rules have to be a JSON object.')) ?>,
        matches: <?= json_encode(__('matches')) ?>,
        anyOf: <?= json_encode(__('any of')) ?>
    };

    var rulesEl = document.getElementById('SharingGroupBlueprintRules');
    var statusEl = document.getElementById('blueprintRulesStatus');
    var errorEl = document.getElementById('blueprintRulesError');
    var treeEl = document.getElementById('blueprintTree');
    var treeWrap = document.getElementById('blueprintTreeWrap');
    var formatBtn = document.getElementById('blueprintFormatBtn');
    var nameEl = document.getElementById('BlueprintName');
    var form = document.getElementById('blueprintForm');
    if (!rulesEl) { return; }

    function setStatus(kind, text) {
        statusEl.className = 'badge bg-' + kind;
        statusEl.style.fontSize = '.65rem';
        statusEl.textContent = text;
    }

    function setError(message) {
        if (!message) {
            errorEl.classList.add('d-none');
            errorEl.textContent = '';
            return;
        }
        errorEl.classList.remove('d-none');
        errorEl.innerHTML = '';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        errorEl.appendChild(icon);
        errorEl.appendChild(document.createTextNode(message));
    }

    /* Walks the parsed rule the way SharingGroupBlueprint::__recursiveEvaluate()
     * does, so what the box shows is what the model will do. */
    function buildTree(node, operand, depth) {
        var wrap = document.createElement('div');
        if (depth > 0) {
            wrap.style.marginLeft = '1rem';
            wrap.style.borderLeft = '1px solid #d8dde3';
            wrap.style.paddingLeft = '.65rem';
        }
        Object.keys(node).forEach(function (key) {
            var row = document.createElement('div');
            row.className = 'd-flex align-items-start gap-2 py-1';

            var badge = document.createElement('span');
            badge.className = 'badge flex-shrink-0 font-monospace';
            badge.style.fontSize = '.65rem';

            if (OPERANDS.indexOf(key) !== -1) {
                badge.classList.add(key === 'NOT' ? 'bg-danger' : 'bg-primary');
                badge.textContent = key;
                row.appendChild(badge);
                wrap.appendChild(row);
                if (node[key] && typeof node[key] === 'object') {
                    wrap.appendChild(buildTree(node[key], key, depth + 1));
                }
                return;
            }

            var known = FILTERS.indexOf(key) !== -1;
            badge.classList.add(known ? 'bg-secondary' : 'bg-warning');
            if (!known) { badge.classList.add('text-dark'); }
            badge.textContent = key;
            row.appendChild(badge);

            var text = document.createElement('span');
            var value = node[key];
            var rendered = Array.isArray(value)
                ? L.anyOf + ' ' + value.join(', ')
                : String(value);
            text.className = known ? 'text-body' : 'text-warning-emphasis';
            text.textContent = (known ? (HINTS[key] || key) : L.unknown)
                + ' ' + L.matches + ' ' + rendered
                + (operand === 'NOT' ? ' (' + 'NOT' + ')' : '');
            row.appendChild(text);
            wrap.appendChild(row);
        });
        return wrap;
    }

    /* First structural problem the model would trip on, if any */
    function findProblem(node, operand) {
        var keys = Object.keys(node);
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            var isOperand = OPERANDS.indexOf(key) !== -1;
            if (isOperand && operand === 'NOT') { return L.notNested; }
            if (isOperand) {
                if (node[key] && typeof node[key] === 'object' && !Array.isArray(node[key])) {
                    var deeper = findProblem(node[key], key);
                    if (deeper) { return deeper; }
                }
                continue;
            }
            if (FILTERS.indexOf(key) === -1) {
                return L.unknownKey.replace('%s', key);
            }
        }
        return null;
    }

    function refresh() {
        var raw = rulesEl.value.trim();
        if (!raw) {
            setStatus('secondary', L.waiting);
            setError(null);
            treeWrap.classList.add('d-none');
            return;
        }
        var parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            setStatus('danger', L.invalid);
            setError(e.message);
            treeWrap.classList.add('d-none');
            return;
        }
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
            setStatus('danger', L.invalid);
            setError(L.objectExpected);
            treeWrap.classList.add('d-none');
            return;
        }

        var problem = findProblem(parsed, 'OR');
        setStatus(problem ? 'warning' : 'success', problem ? L.unknown : L.valid);
        setError(problem);

        treeEl.innerHTML = '';
        treeEl.appendChild(buildTree(parsed, 'OR', 0));
        treeWrap.classList.remove('d-none');
    }

    rulesEl.addEventListener('input', refresh);

    /* Format only when the JSON parses — never destroy what the user typed */
    if (formatBtn) {
        formatBtn.addEventListener('click', function () {
            try {
                rulesEl.value = JSON.stringify(JSON.parse(rulesEl.value), null, 4);
            } catch (e) { /* refresh() already reports it */ }
            refresh();
        });
    }

    /* Palette inserts a snippet at the caret and leaves the cursor inside it */
    function insertAtCaret(text, caretOffsetFromEnd) {
        var start = rulesEl.selectionStart;
        var end = rulesEl.selectionEnd;
        var value = rulesEl.value;
        rulesEl.value = value.slice(0, start) + text + value.slice(end);
        var caret = start + text.length - (caretOffsetFromEnd || 0);
        rulesEl.focus();
        rulesEl.setSelectionRange(caret, caret);
        refresh();
    }

    document.querySelectorAll('.blueprint-insert').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var operand = btn.dataset.insertOperand;
            if (operand) {
                insertAtCaret('"' + operand + '": {\n    \n}', 2);
            } else {
                insertAtCaret('"' + btn.dataset.insertFilter + '": ""', 1);
            }
        });
    });

    /* Both fields are stored NOT NULL, so neither may go out empty */
    if (form) {
        form.addEventListener('submit', function (e) {
            var noName = nameEl && !nameEl.value.trim();
            var noRules = !rulesEl.value.trim();
            if (noName && nameEl) {
                nameEl.style.setProperty('border-bottom-color', '#dc3545', 'important');
                if (!document.getElementById('BlueprintNameError')) {
                    var msg = document.createElement('div');
                    msg.id = 'BlueprintNameError';
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
            if (noRules) {
                setStatus('danger', L.invalid);
                setError(L.rulesRequired);
            }
            if (noName || noRules) {
                e.preventDefault();
                e.stopPropagation();
                (noName ? nameEl : rulesEl).focus();
            }
        });

        if (nameEl) {
            nameEl.addEventListener('input', function () {
                if (!nameEl.value.trim()) { return; }
                nameEl.style.setProperty('border-bottom-color', '#d8dde3', 'important');
                var msg = document.getElementById('BlueprintNameError');
                if (msg) { msg.remove(); }
            });
        }
    }

    refresh();
})();
</script>
