<?php
/*
 * The add/edit modal shared by the blocklists (events, organisations,
 * sightings). They differ only in wording and in the metadata fields their
 * model declares, so the shape lives here once.
 *
 * BlocklistComponent::add() splits `uuids` on newlines and keeps a line only if
 * it is exactly 36 characters long, silently counting the rest as failures —
 * hence the live count below.
 *
 * Required params:
 *   $model       string  'EventBlocklist' | 'OrgBlocklist' | 'SightingBlocklist'
 *   $isEdit      bool
 *   $eyebrow     string  small uppercase label
 *   $title       string  modal title
 *   $description string  one-line explanation of what blocking does
 *   $icon        string  full class attribute of the right-hand glyph
 *   $uuidLabel   string  label of the uuid field
 *   $fields      array   metadata fields, each:
 *                        field, label, placeholder, type ('text'|'textarea'),
 *                        value, rows (textarea only), hint (optional)
 * Optional params:
 *   $uuidValue   string  the stored uuid, shown read-only when editing
 *   $entryId     mixed   shown in the footer when editing
 */

$uuidValue = $uuidValue ?? '';
$entryId = $entryId ?? null;
$formId = lcfirst($model) . 'Form';

echo $this->Form->create($model, [
    'id' => $formId,
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => $eyebrow,
    'title' => $title,
    'description' => $description,
    'icon' => $icon,
    'isEdit' => $isEdit,
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── UUID(S) ─────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 text-primary fw-bold
                            text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= h($uuidLabel) ?>
                    <?php if (!$isEdit): ?>
                        <span class="badge bg-primary"
                              style="font-size:.55rem; opacity:.8; font-weight:700;">
                            <?= __('REQUIRED') ?>
                        </span>
                    <?php endif; ?>
                </div>
                <?php if (!$isEdit): ?>
                    <div class="d-flex align-items-center gap-1"
                         id="blocklistCounts"></div>
                <?php endif; ?>
            </div>

            <?php if ($isEdit): ?>
                <!-- The uuid identifies the entry; only its metadata is editable -->
                <div class="border rounded px-3 py-2 bg-light d-flex
                            align-items-center gap-2">
                    <i class="fas fa-lock text-muted" style="font-size:.7rem;"></i>
                    <code class="text-body"><?= h($uuidValue) ?></code>
                </div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('The UUID cannot be changed — remove this entry and add the new one instead.'),
                ]) ?>
            <?php else: ?>
                <?= $this->Form->textarea('uuids', [
                    'id' => 'BlocklistUuids',
                    'class' => 'w-100 rounded-2 p-3',
                    'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                        . ' border:1px solid #d8dde3; resize:vertical;'
                        . ' outline:none; font-size:.85rem; min-height:150px;'
                        . ' color:inherit; font-family:monospace;',
                    'rows' => 6,
                    'spellcheck' => 'false',
                    'placeholder' => "5f2e1c3a-1111-4222-8333-444455556666\n…",
                ]) ?>
                <div id="blocklistUuidsError" class="d-none text-danger
                            d-flex align-items-start gap-1 mt-1"
                     style="font-size:.75rem;"></div>
                <?= $this->element('genericElementsBS5/Forms/field_hint', [
                    'text' => __('One UUID per line — a line that is not a full 36-character UUID is skipped.'),
                ]) ?>
            <?php endif; ?>
        </div>

        <!-- ── METADATA ────────────────────────────────────────── -->
        <?php foreach ($fields as $field): ?>
            <div class="w-100 px-2">
                <?= $this->element('genericElementsBS5/Forms/section_label', [
                    'accent' => 'primary',
                    'label' => h($field['label']),
                ]) ?>
                <?php
                $common = [
                    'class' => 'form-control',
                    'style' => 'border-color:#d8dde3;',
                    'value' => $field['value'] ?? '',
                    'placeholder' => $field['placeholder'] ?? '',
                    'autocomplete' => 'off',
                ];
                if (($field['type'] ?? 'text') === 'textarea') {
                    $common['rows'] = $field['rows'] ?? 2;
                    echo $this->Form->textarea($field['field'], $common);
                } else {
                    echo $this->Form->text($field['field'], $common);
                }
                ?>
                <?php if (!empty($field['hint'])): ?>
                    <?= $this->element('genericElementsBS5/Forms/field_hint', [
                        'text' => h($field['hint']),
                    ]) ?>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'isEdit' => $isEdit,
        'meta' => $isEdit && !empty($entryId) ? [['label' => __('Entry'), 'id' => $entryId]] : [],
        'hint' => __('Blocking does not remove what is already on this instance.'),
        'submit' => [
            'label' => $isEdit ? __('Save Changes') : __('Add to Blocklist'),
            'icon' => 'fas fa-' . ($isEdit ? 'floppy-disk' : 'ban'),
        ],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<?php if (!$isEdit): ?>
<script>
(function () {
    var L = {
        accepted: <?= json_encode(__('%s UUID(s)')) ?>,
        rejected: <?= json_encode(__('%s line(s) skipped')) ?>,
        none: <?= json_encode(__('Nothing to add')) ?>,
        required: <?= json_encode(__('Please provide at least one UUID.')) ?>,
        skippedLines: <?= json_encode(__('Skipped line(s): %s — a UUID is 36 characters long.')) ?>
    };
    var FORM_ID = <?= json_encode($formId, JSON_HEX_TAG | JSON_HEX_AMP
        | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    var uuidsEl = document.getElementById('BlocklistUuids');
    var countsEl = document.getElementById('blocklistCounts');
    var errorEl = document.getElementById('blocklistUuidsError');
    var form = document.getElementById(FORM_ID);
    if (!uuidsEl) { return; }

    function badge(text, kind) {
        var span = document.createElement('span');
        span.className = 'badge ' + kind;
        span.style.fontSize = '.6rem';
        span.textContent = text;
        return span;
    }

    /* Mirrors BlocklistComponent::add(): the value is split on newlines and a
     * line only counts when it is exactly 36 characters long. */
    function read() {
        var raw = uuidsEl.value.trim();
        if (!raw) { return { accepted: 0, rejected: [] }; }
        var accepted = 0;
        var rejected = [];
        raw.split('\n').forEach(function (line, index) {
            if (line.trim().length === 36) { accepted++; }
            else { rejected.push(index + 1); }
        });
        return { accepted: accepted, rejected: rejected };
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

    function refresh() {
        var state = read();
        countsEl.innerHTML = '';
        if (!state.accepted && !state.rejected.length) {
            countsEl.appendChild(badge(L.none, 'text-bg-secondary'));
        } else {
            countsEl.appendChild(badge(L.accepted.replace('%s', state.accepted),
                state.accepted ? 'text-bg-success' : 'text-bg-secondary'));
            if (state.rejected.length) {
                countsEl.appendChild(badge(
                    L.rejected.replace('%s', state.rejected.length),
                    'text-bg-warning text-dark'));
            }
        }
        setError(state.rejected.length
            ? L.skippedLines.replace('%s', state.rejected.join(', '))
            : null);
        return state;
    }

    uuidsEl.addEventListener('input', refresh);

    if (form) {
        form.addEventListener('submit', function (e) {
            var state = refresh();
            if (state.accepted) { return; }
            e.preventDefault();
            e.stopPropagation();
            uuidsEl.style.setProperty('border-color', '#dc3545', 'important');
            setError(L.required);
            uuidsEl.focus();
        });
        uuidsEl.addEventListener('input', function () {
            if (uuidsEl.value.trim()) {
                uuidsEl.style.setProperty('border-color', '#d8dde3', 'important');
            }
        });
    }

    refresh();
})();
</script>
<?php endif; ?>
