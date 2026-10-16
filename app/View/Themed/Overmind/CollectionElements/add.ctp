<?php
$collectionId = $this->request->params['pass'][0] ?? null;

$types = $dropdownData['types'] ?? [];


$typeStyles = $this->ElementType->styles();
$typeOptions = [];
foreach ($types as $value => $label) {
    $typeOptions[$value] = $this->ElementType->label($value);
}

echo $this->Form->create('CollectionElement', [
    'id' => 'collectionElementForm',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Collections'),
    'title' => __('Add Element to Collection'),
    'description' => __('Attach an event, galaxy cluster, attribute or object by its UUID, or add a value.'),
    'icon' => 'fas fa-link',
]) ?>


<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── ELEMENT UUID ────────────────────────────────────── -->
        <div class="w-100 px-2" id="collectionElementUuidBox">
            <div class="d-flex align-items-center gap-2 text-accent fw-bold
                        text-uppercase mb-2"
                 style="font-size:.65rem; letter-spacing:.1em;">
                <?= __('Element UUID') ?>
                <span class="badge bg-primary"
                      style="font-size:.55rem; opacity:.8; font-weight:700;">
                    <?= __('REQUIRED') ?>
                </span>
            </div>
            <?= $this->Form->text('element_uuid', [
                'id' => 'CollectionElementElementUuid',
                'class' => 'w-100 border-0 bg-transparent fs-5 py-1 font-monospace',
                'style' => 'border-bottom:1px solid var(--misp-field-line, #d8dde3) !important;'
                    . ' outline:none;',
                'maxlength' => 36,
                'placeholder' => 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX',
                'autocomplete' => 'off',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('The RFC 4122 UUID of the event, galaxy cluster, attribute or object to attach.'),
            ]) ?>
        </div>

        <!-- ── VALUE ───────────────────────────────────────────── -->
        <div class="w-100 px-2 d-none" id="collectionElementValueBox">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Value'),
                'required' => true,
                'for' => 'CollectionElementValue',
            ]) ?>
            <?= $this->Form->text('value', [
                'id' => 'CollectionElementValue',
                'class' => 'form-control font-monospace',
                'autocomplete' => 'off',
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('An IP address, a domain, a hash — any value. Its text shows to readers who can see an attribute carrying it.'),
            ]) ?>
        </div>

        <!-- ── ELEMENT TYPE ────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Element Type'),
            ]) ?>
            <?= $this->Form->select('element_type', $typeOptions, [
                'id' => 'collection-element-type-select',
                'class' => 'form-select',
                'empty' => __('Detect from the UUID'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Left on detection, MISP resolves the type by looking the UUID up locally. Pick one to attach an element this instance does not hold yet.'),
            ]) ?>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Description'),
            ]) ?>
            <?= $this->Form->textarea('description', [
                'class' => 'form-control',
                'rows' => 3,
                'style' => 'border-color:var(--misp-field-line, #d8dde3);',
                'placeholder' => __('Briefly describe why this element belongs to the collection…'),
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'meta' => !empty($collectionId) ? [['label' => __('Collection'), 'id' => $collectionId]] : [],
        'submit' => ['label' => __('Attach Element')],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var TYPE_STYLES = <?= json_encode($typeStyles, JSON_FORCE_OBJECT
        | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
    var UUID_REQUIRED = <?= json_encode(__('Please provide the UUID of the element to attach.')) ?>;
    var UUID_INVALID = <?= json_encode(__('This is not a valid UUID.')) ?>;
    var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    var VALUE_REQUIRED = <?= json_encode(__('Please provide the value to add.')) ?>;

    /* Element type — the badge shape the distribution and collection type
     * selects use, tinted with the entity's own colour. */
    function renderType(data, escape, compact) {
        if (!data.value) {
            return '<div class="text-muted' + (compact ? '' : ' py-1') + '">'
                + escape(data.text) + '</div>';
        }
        var s = TYPE_STYLES[data.value]
            || { icon: 'fas fa-cube', color: 'var(--bs-secondary)', ink: '#fff' };
        return '<div class="d-flex align-items-center gap-2' + (compact ? '' : ' py-1') + '">'
            + '<span class="badge d-inline-flex align-items-center'
                + (compact ? ' px-1' : ' px-2 py-1') + '" style="'
                + 'background:' + s.color + ';color:' + s.ink + ';'
                + (compact ? 'font-size:.65rem;' : '') + '">'
            + '<i class="' + escape(s.icon) + '"></i>'
            + '</span>'
            + '<span>' + escape(data.text) + '</span>'
            + '</div>';
    }

    var typeEl = document.getElementById('collection-element-type-select');
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

    var uuidEl = document.getElementById('CollectionElementElementUuid');
    var valueEl = document.getElementById('CollectionElementValue');
    var form = document.getElementById('collectionElementForm');
    var isValue = function () { return typeEl && typeEl.value === 'AttributeValue'; };
    /* Hidden, never disabled: a disabled input is not posted, which breaks
       the form's field hash. The model ignores whichever does not apply. */
    var applyType = function () {
        document.getElementById('collectionElementUuidBox').classList.toggle('d-none', isValue());
        document.getElementById('collectionElementValueBox').classList.toggle('d-none', !isValue());
    };
    if (typeEl && uuidEl && valueEl) {
        typeEl.addEventListener('change', applyType);
        applyType();
    }
    if (form && uuidEl) {
        var errorId = 'collectionElementUuidError';

        var showError = function (message) {
            uuidEl.style.setProperty('border-bottom-color', 'var(--misp-tone-red-solid, #dc3545)', 'important');
            var msg = document.getElementById(errorId);
            if (!msg) {
                msg = document.createElement('div');
                msg.id = errorId;
                msg.className = 'text-danger d-flex align-items-center gap-1';
                msg.style.fontSize = '.75rem';
                msg.style.marginTop = '.35rem';
                var icon = document.createElement('i');
                icon.className = 'fas fa-circle-exclamation';
                msg.appendChild(icon);
                msg.appendChild(document.createTextNode(''));
                uuidEl.parentNode.insertBefore(msg, uuidEl.nextSibling);
            }
            msg.lastChild.textContent = message;
        };

        var clearError = function () {
            uuidEl.style.setProperty('border-bottom-color', 'var(--misp-field-line, #d8dde3)', 'important');
            var msg = document.getElementById(errorId);
            if (msg) { msg.remove(); }
        };

        form.addEventListener('submit', function (e) {
            if (isValue()) {
                if (valueEl.value.trim()) { return; }
                e.preventDefault();
                e.stopPropagation();
                valueEl.classList.add('is-invalid');
                valueEl.setAttribute('title', VALUE_REQUIRED);
                valueEl.focus();
                return;
            }
            var value = uuidEl.value.trim();
            if (value && UUID_RE.test(value)) { return; }
            e.preventDefault();
            e.stopPropagation();
            showError(value ? UUID_INVALID : UUID_REQUIRED);
            uuidEl.focus();
        });

        uuidEl.addEventListener('input', function () {
            if (UUID_RE.test(uuidEl.value.trim())) { clearError(); }
        });
    }
})();
</script>
