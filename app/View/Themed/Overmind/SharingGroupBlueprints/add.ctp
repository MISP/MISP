<?php
$isEdit = $this->request->params['action'] === 'edit';

$blueprint = $this->request->data['SharingGroupBlueprint'] ?? [];

/* Stored minified; json_field pretty-prints it for editing, and leaves an
 * unparseable value untouched so it can be repaired by hand. */
$currentRules = $blueprint['rules'] ?? '';

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

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Sharing Group Blueprints'),
    'title' => $isEdit ? __('Edit Blueprint') : __('Add Blueprint'),
    'description' => __('A rule over organisations, evaluated on demand to build and keep a sharing group up to date.'),
    'icon' => 'fas fa-sitemap',
    'isEdit' => $isEdit,
]) ?>

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
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Also used as the name of the sharing group the blueprint creates.'),
            ]) ?>
        </div>

        <!-- ── RULES ───────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?php
            /* Palette: click to insert at the caret. It belongs to the field
             * rather than to the screen, so it rides the element's `above`
             * slot and stays under the field's own label. */
            ob_start();
            ?>
            <div class="d-flex flex-wrap align-items-center gap-1 mb-2 mt-2">
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
            <?php $palette = ob_get_clean(); ?>

            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'rules',
                'label' => __('Rules'),
                'required' => true,
                'shape' => 'object',
                'id' => 'SharingGroupBlueprintRules',
                'value' => $currentRules,
                'rows' => 14,
                'minHeight' => '240px',
                'placeholder' => "{\n    \"AND\": {\n        \"org_sector\": \"Financial\",\n        \"org_nationality\": [\"FR\", \"BE\"]\n    }\n}",
                'above' => $palette,
                'preview' => true,
                'previewLabel' => __('How this rule reads'),
            ]) ?>

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

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($id) ? [['label' => __('Blueprint'), 'id' => $id]] : [],
        'hint' => __('Nothing is created until the blueprint is executed from the index.'),
        'submit' => ['label' => $isEdit ? __('Save Changes') : __('Add Blueprint')],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var FILTERS = <?= json_encode($filterNames, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var OPERANDS = <?= json_encode($operandList, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var HINTS = <?= json_encode($filterHints, JSON_FORCE_OBJECT | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var L = {
        nameRequired: <?= json_encode(__('Please provide a name for the blueprint.')) ?>,
        notNested: <?= json_encode(__('A NOT branch cannot hold another branch — the model refuses it.')) ?>,
        unknownKey: <?= json_encode(__('"%s" is neither an operator nor a known filter, so it would match nothing.')) ?>,
        unknown: <?= json_encode(__('Unknown key')) ?>,
        matches: <?= json_encode(__('matches')) ?>,
        anyOf: <?= json_encode(__('any of')) ?>
    };

    var rulesEl = document.getElementById('SharingGroupBlueprintRules');
    var nameEl = document.getElementById('BlueprintName');
    var form = document.getElementById('blueprintForm');
    if (!rulesEl) { return; }

    /* Walks the parsed rule the way SharingGroupBlueprint::__recursiveEvaluate()
     * does, so what the box shows is what the model will do. */
    function buildTree(node, operand, depth) {
        var wrap = document.createElement('div');
        if (depth === 0) {
            wrap.className = 'p-3';
        } else {
            wrap.style.marginLeft = '1rem';
            wrap.style.borderLeft = '1px solid var(--bs-border-color)';
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

    /* The field parses, reports and re-indents on its own; what is specific to
     * a blueprint is the reading of the rule and the vocabulary check. */
    rulesEl.addEventListener('misp:json-change', function (e) {
        var field = e.detail.field;
        if (!e.detail.valid) {
            field.setPreview(null);
            return;
        }
        field.setProblem(findProblem(e.detail.parsed, 'OR'));
        field.setPreview(buildTree(e.detail.parsed, 'OR', 0));
    });

    /* Palette inserts a snippet at the caret and leaves the cursor inside it */
    function insertAtCaret(text, caretOffsetFromEnd) {
        var start = rulesEl.selectionStart;
        var end = rulesEl.selectionEnd;
        var value = rulesEl.value;
        rulesEl.value = value.slice(0, start) + text + value.slice(end);
        var caret = start + text.length - (caretOffsetFromEnd || 0);
        rulesEl.focus();
        rulesEl.setSelectionRange(caret, caret);
        if (rulesEl.jsonField) { rulesEl.jsonField.refresh(); }
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

    /* The name is stored NOT NULL too; the rules are the json_field's own
     * business, and its guard on this form already refuses an empty one. */
    if (form) {
        form.addEventListener('submit', function (e) {
            if (!nameEl || nameEl.value.trim()) { return; }
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
            nameEl.style.setProperty('border-bottom-color', '#dc3545', 'important');
            e.preventDefault();
            e.stopPropagation();
            nameEl.focus();
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
})();
</script>
