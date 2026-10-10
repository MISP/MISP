<?php
/*
 * Attach one element — an event, a galaxy cluster — to a collection.
 *
 * "Add it to a collection" and "add it to a collection I do not have yet" are
 * the same intent, so they are one control: the picker's first entry is
 * New collection, and choosing it unfolds Collections/add right here. 
 * The two forms are siblings, never nested: everything the picker owns — the
 * attach banner, the element description, the footer — hides while the
 * new-collection form is open, and that form renders the same three itself, so
 * exactly one of each is reachable at any moment.
 *
 * Set by CollectionElementsController::addElementToCollection():
 *   $dropdownData['collections']  id => name, the collections of the user's org
 *   $alreadyInCollectionIds       ids among those that already hold the element
 *   $elementType, $elementUuid    what is being attached
 */

$collections = $dropdownData['collections'] ?? [];
$alreadyIn = array_map('strval', $alreadyInCollectionIds ?? []);

// Not a collection id — the select's own value for "unfold the add form".
$newValue = '__new__';

$newCollectionUrl = $baseurl . '/collections/add?embedded=1&attach_element_type='
    . rawurlencode($elementType) . '&attach_element_uuid=' . rawurlencode($elementUuid);

/* A collection that already holds the element stays in the list, suffixed and
 * disabled: the user recognises it, and cannot pick a no-op. */
$options = [$newValue => __('New collection')];
$firstSelectable = null;
foreach ($collections as $id => $name) {
    $taken = in_array((string)$id, $alreadyIn, true);
    $options[$id] = $taken
        ? sprintf('%s — %s', $name, __('already added'))
        : $name;
    if (!$taken && $firstSelectable === null) {
        $firstSelectable = $id;
    }
}
/* Nothing to pick means the user is here to create one — start there. */
$selected = $firstSelectable ?? $newValue;
$startsNew = $selected === $newValue;


echo $this->Form->create('CollectionElement', [
    'id' => 'addElementToCollectionForm',
    'novalidate' => true,
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'primary',
    'eyebrow' => __('Collections'),
    'title' => __('Add to a Collection'),
    'description' => __('Collections group shared data into buckets — a campaign, an intrusion set, a piece of research. Adding an element does not change how it is distributed.'),
    'icon' => 'fas fa-folder-open',
    'titleIcon' => 'fas fa-folder-plus',
]) ?>

<div class="container-fluid px-4 py-4<?= $startsNew ? ' pb-0' : '' ?>" id="collectionPickerBody">

    <div class="d-flex flex-column gap-4 px-2">

        <!-- ── COLLECTION ──────────────────────────────────────── -->
        <div class="w-100">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Collection'),
                'required' => true,
                'for' => 'CollectionElementCollectionId',
            ]) ?>
            <?= $this->Form->select('collection_id', $options, [
                'id' => 'CollectionElementCollectionId',
                'class' => 'form-select',
                'empty' => false,
                'disabled' => $alreadyIn,
                'value' => $selected,
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Only the collections of your organisation are listed. Pick New collection to create one without leaving this window.'),
            ]) ?>
        </div>

        <!-- ── ELEMENT BEING ATTACHED ───────-->
        <div class="alert alert-light border d-flex align-items-center gap-3 mb-0 js-picker-existing<?= $startsNew ? ' d-none' : '' ?>"
             role="alert" style="border-color:var(--bs-primary) !important;">
            <i class="fas fa-link text-primary"></i>
            <div class="flex-grow-1">
                <div class="fw-semibold" style="font-size:.85rem;">
                    <?= __('This %s will be attached', h($elementType)) ?>
                </div>
                <div class="text-muted" style="font-size:.75rem; margin-top:.15rem;">
                    <code><?= h($elementUuid) ?></code>
                </div>
            </div>
        </div>

        <!-- ── DESCRIPTION ─────────────────────────────────────── -->
        <div class="w-100 js-picker-existing<?= $startsNew ? ' d-none' : '' ?>">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'primary',
                'label' => __('Description'),
                'for' => 'CollectionElementDescription',
            ]) ?>
            <?= $this->Form->textarea('description', [
                'id' => 'CollectionElementDescription',
                'class' => 'form-control',
                'rows' => 3,
                'placeholder' => __('Why this element belongs in the collection — optional.'),
            ]) ?>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Shown next to the element in the collection, nowhere else.'),
            ]) ?>
        </div>

    </div>

    <div class="js-picker-existing<?= $startsNew ? ' d-none' : '' ?>">
        <?= $this->element('genericElementsBS5/Forms/modal_footer', [
            'accent' => 'primary',
            'hint' => __('The element keeps its own distribution — a collection never widens it.'),
            'submit' => [
                'label' => __('Add to Collection'),
                'icon' => 'fas fa-folder-plus',
                'type' => 'submit',
            ],
        ]) ?>
    </div>

</div>

<?= $this->Form->end() ?>

<!-- The new-collection form, fetched on first use. Outside the picker's form:
     two <form>s side by side, never one inside the other. -->
<div id="newCollectionBox"<?= $startsNew ? '' : ' class="d-none"'?>></div>

<script type="application/json" id="collectionPickerConfig">
<?= json_encode([
    'newValue' => $newValue,
    'url' => $newCollectionUrl,
    'loading' => __('Loading the collection form…'),
    'failed' => __('Could not load the collection form.'),
], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>
</script>

<script>
function initCollectionPicker() {
    var cfg = JSON.parse(document.getElementById('collectionPickerConfig').textContent);
    var select = document.getElementById('CollectionElementCollectionId');
    var body = document.getElementById('collectionPickerBody');
    var box = document.getElementById('newCollectionBox');
    var form = document.getElementById('addElementToCollectionForm');
    if (!select || !box || !body) { return; }

    /* Its own TomSelect rather than the shared `tom-select` class: the New
       collection entry is an action, not a collection, and has to read as one.
       openModal runs this script before initTomSelect(), which then skips a
       select that already has one. */
    function renderOption(data, escape, compact) {
        var isNew = data.value === cfg.newValue;
        return '<div class="d-flex align-items-center gap-2' + (compact ? '' : ' py-1') + '">'
            + '<span class="badge d-inline-flex align-items-center' + (compact ? ' px-1' : ' py-1')
                + '" style="background:rgba(var(--bs-primary-rgb),.12);'
                + 'color:var(--bs-primary); border:1px solid rgba(var(--bs-primary-rgb),.25);'
                + (compact ? 'font-size:.65rem;' : '') + '">'
            + '<i class="fas fa-' + (isNew ? 'circle-plus' : 'folder') + '"></i>'
            + '</span>'
            + '<span' + (isNew ? ' class="fw-semibold"' : '') + '>' + escape(data.text) + '</span>'
            + '</div>';
    }
    if (typeof TomSelect !== 'undefined' && !select.tomselect) {
        new TomSelect(select, {
            create: false,
            persist: false,
            render: {
                option: function (d, escape) { return renderOption(d, escape, false); },
                item: function (d, escape) { return renderOption(d, escape, true); }
            }
        });
    }

    /* `.d-flex` carries !important, so visibility is a class, never a style. */
    function toggle(nodes, hidden) {
        nodes.forEach(function (el) { el.classList.toggle('d-none', hidden); });
    }

    var loaded = false;
    function loadNewCollectionForm() {
        if (loaded) { return; }
        loaded = true;
        box.innerHTML = '<div class="text-center text-muted py-4">'
            + '<div class="spinner-border spinner-border-sm me-2" role="status"></div>'
            + cfg.loading + '</div>';
        fetch(cfg.url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
            .then(function (r) {
                if (!r.ok) { throw new Error(r.status); }
                return r.text();
            })
            .then(function (html) {
                box.innerHTML = html;
                // innerHTML does not run <script>, and the add form brings its
                // own (type TomSelect, name counter, submit guard).
                box.querySelectorAll('script:not([type="application/json"])')
                    .forEach(function (old) {
                        var s = document.createElement('script');
                        if (old.src) { s.src = old.src; }
                        else { s.textContent = '(function(){\n' + old.textContent + '\n})();'; }
                        document.body.appendChild(s);
                        document.body.removeChild(s);
                    });
                if (typeof initTomSelect === 'function') { initTomSelect(box); }
                if (typeof initChoiceFields === 'function') { initChoiceFields(box); }
                if (typeof initCollectionForm === 'function') { initCollectionForm(box); }
            })
            .catch(function () {
                loaded = false;
                box.innerHTML = '<div class="text-center text-danger py-4 small">'
                    + '<i class="fas fa-exclamation-triangle me-2"></i>' + cfg.failed + '</div>';
            });
    }

    function apply() {
        var isNew = select.value === cfg.newValue;
        toggle(Array.prototype.slice.call(body.querySelectorAll('.js-picker-existing')), isNew);
        box.classList.toggle('d-none', !isNew);
        // The picker's own padding would stack on top of the embedded form's.
        if (body) { body.classList.toggle('pb-0', isNew); }
        if (isNew) { loadNewCollectionForm(); }
    }

    select.addEventListener('change', apply);
    apply();

    /* Belt and braces: the picker's submit is hidden in New collection mode, so
       this only ever fires if something else submits the form. */
    if (form) {
        form.addEventListener('submit', function (e) {
            if (select.value === cfg.newValue) { e.preventDefault(); }
        });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCollectionPicker);
} else {
    initCollectionPicker();
}
</script>
