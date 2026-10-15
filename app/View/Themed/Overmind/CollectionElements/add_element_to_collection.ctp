<?php
/*
 * Attach one element — an event, a cluster, an attribute, an object, a value —
 * to a collection.
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
 *   $elementValue                 the literal, for a Value element
 */
App::uses('ValueUrlTool', 'Tools/ValueIntelligence');
$elementValue = $elementValue ?? null;

$collections = $dropdownData['collections'] ?? [];
$alreadyIn = array_map('strval', $alreadyInCollectionIds ?? []);

// Not a collection id — the select's own value for "unfold the add form".
$newValue = '__new__';

$newCollectionUrl = $baseurl . '/collections/add?embedded=1&attach_element_type='
    . rawurlencode($elementType) . '&attach_element_uuid='
    . rawurlencode($elementValue !== null ? ValueUrlTool::encode($elementValue) : $elementUuid);

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
            <i class="fas fa-link text-accent"></i>
            <div class="flex-grow-1">
                <div class="fw-semibold" style="font-size:.85rem;">
                    <?= __('This %s will be attached', h($elementType)) ?>
                </div>
                <div class="text-muted" style="font-size:.75rem; margin-top:.15rem;">
                    <code class="text-break"><?= h($elementValue ?? $elementUuid) ?></code>
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
    'saved' => __('Element added to the Collection.'),
    'created' => __('Collection created, with the element in it.'),
    'saveFailed' => __('Element could not be added to the Collection.'),
    'elementType' => $elementType,
    'elementUuid' => $elementUuid,
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
            + '<div class="misp-loader misp-loader-sm mb-2" role="status"></div>'
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
                var created = box.querySelector('form');
                if (created) {
                    saveInPlace(created, cfg.created, function (body) {
                        return body.Collection ? body.Collection.id : null;
                    });
                }
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

    /* openModal runs this before it shows the modal, and Bootstrap ignores a
       hide() while the modal is still fading in. */
    var modalEl = form ? form.closest('.modal') : null;
    var shown = !!modalEl && modalEl.classList.contains('show');
    if (modalEl && !shown) {
        modalEl.addEventListener('shown.bs.modal', function () { shown = true; }, { once: true });
    }
    function closeModal() {
        if (!modalEl || typeof bootstrap === 'undefined') { return; }
        var modal = bootstrap.Modal.getOrCreateInstance(modalEl);
        if (shown) { modal.hide(); return; }
        modalEl.addEventListener('shown.bs.modal', function () { modal.hide(); }, { once: true });
    }

    /* Both forms save in place: a full post would redirect, which puts an
       event page back on its first tab and empties the /values/index
       worklist. The token goes in the header, where it is checked but not
       spent, so a refused save can be sent again. */
    function saveInPlace(target, savedMessage, collectionIdOf) {
        target.addEventListener('submit', function (e) {
            if (e.defaultPrevented) { return; }
            e.preventDefault();
            var submit = target.querySelector('[type="submit"]')
                || (target.closest('.modal-content') || document).querySelector('[type="submit"]');
            if (submit) { submit.disabled = true; }
            var headers = { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
            var token = target.querySelector('[name="data[_Token][key]"]');
            if (token) { headers['X-CSRF-Token'] = token.value; }
            fetch(target.action, {
                method: 'POST',
                credentials: 'same-origin',
                headers: headers,
                body: new FormData(target)
            })
                .then(function (r) {
                    return r.json().catch(function () { return {}; }).then(function (body) {
                        return { ok: r.ok && body.saved !== false, body: body };
                    });
                })
                .then(function (res) {
                    var message = res.ok
                        ? res.body.message || savedMessage
                        : res.body.message || res.body.errors || cfg.saveFailed;
                    if (typeof message !== 'string') { message = res.ok ? savedMessage : cfg.saveFailed; }
                    if (!res.ok) { throw new Error(message); }
                    closeModal();
                    if (typeof showToast === 'function') { showToast(message, 'success'); }
                    document.dispatchEvent(new CustomEvent('misp:collection-element-added', {
                        detail: { type: cfg.elementType, uuid: cfg.elementUuid, collectionId: collectionIdOf(res.body) }
                    }));
                })
                .catch(function (err) {
                    if (submit) { submit.disabled = false; }
                    if (typeof showToast === 'function') { showToast(err.message || cfg.saveFailed, 'danger'); }
                });
        });
    }

    if (form) {
        // The picker's submit is hidden in New collection mode.
        form.addEventListener('submit', function (e) {
            if (select.value === cfg.newValue) { e.preventDefault(); }
        });
        saveInPlace(form, cfg.saved, function () { return select.value; });
    }
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initCollectionPicker);
} else {
    initCollectionPicker();
}
</script>
