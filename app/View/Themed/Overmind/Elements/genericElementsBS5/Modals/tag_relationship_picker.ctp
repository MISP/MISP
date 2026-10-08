<?php
/*
 * Modal that puts one relationship type on a selection of an object's tags or
 * galaxy clusters.
 *
 * The stock theme edits a relationship one row at a time, from a pencil on
 * every chip (/tags/modifyTagRelationship/<scope>/<connectorId>, a generic
 * select whose "custom" entry carries a second free-text field). This is the
 * same write the other way round: the relationship is picked once, then the
 * rows it lands on - which is what a card or a column listing them all wants.
 *
 * A cluster rides on the same connector row as a tag, so tags and clusters are
 * one modal: only the chip, the accent and the wording change with $kind.
 *
 * Required params:
 *   $saveUrl             string  POST target, takes JSON
 *                                { relationship, tag_connector_ids }
 *   $uid                 string  unique DOM/scope id (e.g. 'evt-tags-12')
 *   $rows                [{connector_id, id, name, colour, galaxy, local,
 *                          relationship, editable}, ...] - colour for a tag,
 *                          galaxy for a cluster
 *   $relationshipOptions [{name, description, highlighted}, ...]
 *   $mayModify           bool    false renders the list read-only
 * Optional params:
 *   $kind                'tag' (default) or 'galaxy'
 *   $headerEyebrow       string  small uppercase label
 *   $reloadHook          string  window['<hook>' + uid] called after a save;
 *                                falls back to the event-view index reload
 */

$kind          = ($kind ?? 'tag') === 'galaxy' ? 'galaxy' : 'tag';
$isGalaxy      = $kind === 'galaxy';
$accent        = $isGalaxy ? 'galaxy' : 'tag';
$headerEyebrow = $headerEyebrow ?? ($isGalaxy ? __('Galaxies') : __('Tags'));
$reloadHook    = $reloadHook ?? '';
$rows          = $rows ?? [];
$selectId      = $uid . '-rel-select';

/* One chip per row, drawn by the same badge element the surfaces around this
   modal use - so a row here looks like the row it came from. */
$badge = function (array $row) use ($isGalaxy) {
    if ($isGalaxy) {
        return $this->element('genericElementsBS5/Badges/galaxy_cluster', [
            'cluster' => [
                'id'     => $row['id'] ?? null,
                'value'  => $row['name'],
                'galaxy' => $row['galaxy'] ?? '',
            ],
            'local' => !empty($row['local']),
            'hiddenClass' => '',
            'relationship' => $row['relationship'],
        ]);
    }

    return $this->element('genericElementsBS5/Badges/tag', [
        'tag' => [
            'id'     => $row['id'] ?? null,
            'name'   => $row['name'],
            'colour' => $row['colour'] ?? '#0088cc',
        ],
        'local' => !empty($row['local']),
        'hiddenClass' => '',
        'showFavourite' => false,
        'relationship' => $row['relationship'],
    ]);
};
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => $accent,
    'eyebrow' => $headerEyebrow,
    'title' => $isGalaxy
        ? __('Edit Cluster Relationships')
        : __('Edit Tag Relationships'),
    'description' => $isGalaxy
        ? __('A relationship says how this object relates to the cluster — "mitigates", "targets", "attributed-to". It is stored on the attachment, so the same cluster can carry a different relationship elsewhere.')
        : __('A relationship says how this object relates to the tag — "mitigates", "targets", "attributed-to". It is stored on the attachment, so the same tag can carry a different relationship elsewhere.'),
    'titleIcon' => 'fas fa-pen-to-square',
    'icon' => 'fas fa-diagram-project',
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── RELATIONSHIP ────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => $accent,
                'label' => __('Relationship'),
                'for' => $selectId,
            ]) ?>
            <select id="<?= h($selectId) ?>" class="form-select">
                <option value=""><?= __('— Remove relationship —') ?></option>
                <?php foreach ($relationshipOptions as $rel): ?>
                    <option value="<?= h($rel['name']) ?>"
                            data-desc="<?= h($rel['description'] ?? '') ?>">
                        <?= h($rel['name']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => $isGalaxy
                    ? __('Pick a type from the object-relationship vocabulary, or type your own and press Enter. "No relationship" removes the one the selected clusters carry.')
                    : __('Pick a type from the object-relationship vocabulary, or type your own and press Enter. "No relationship" removes the one the selected tags carry.'),
            ]) ?>
        </div>

        <!-- ── ROWS TO APPLY IT TO ─────────────────────────────── -->
        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => $accent,
                'label' => __('Apply to'),
                /* An attachment is a row of the connector table, so the same
                   tag attached locally and globally is two of them. The
                   label's text-uppercase does the shouting. */
                'badge' => sprintf(
                    $isGalaxy
                        ? __n('%s attached cluster', '%s attached clusters', count($rows))
                        : __n('%s attached tag', '%s attached tags', count($rows)),
                    count($rows)
                ),
            ]) ?>

            <?php if (empty($rows)): ?>

                <div class="d-flex flex-column align-items-center justify-content-center
                            text-muted py-4 border rounded-2">
                    <span class="misp-icon misp-icon-<?= $isGalaxy ? 'galaxy' : 'tag' ?> misp-hexagone mb-2 opacity-50"
                          style="font-size:2em;"></span>
                    <p class="mb-0 small fw-semibold">
                        <?= $isGalaxy
                            ? __('No cluster to apply a relationship to.')
                            : __('No tag to apply a relationship to.') ?>
                    </p>
                </div>

            <?php else: ?>

                <div class="d-flex align-items-center gap-2 mb-2 flex-wrap">
                    <div class="input-group input-group-sm" style="max-width:240px;">
                        <span class="input-group-text border-end-0 bg-white">
                            <i class="fas fa-search text-muted small"></i>
                        </span>
                        <input type="search"
                               id="<?= h($uid) ?>-rel-search"
                               class="form-control border-start-0 ps-0"
                               placeholder="<?= $isGalaxy ? __('Filter clusters…') : __('Filter tags…') ?>"
                               autocomplete="off"
                               aria-label="<?= $isGalaxy ? __('Filter clusters') : __('Filter tags') ?>">
                    </div>
                    <?php if ($mayModify): ?>
                        <button type="button" class="btn btn-sm btn-outline-<?= h($accent) ?>"
                                id="<?= h($uid) ?>-rel-all">
                            <?= __('Select all') ?>
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-secondary"
                                id="<?= h($uid) ?>-rel-none">
                            <?= __('Clear selection') ?>
                        </button>
                    <?php endif; ?>
                    <span class="small text-muted ms-auto" id="<?= h($uid) ?>-rel-count"></span>
                </div>

                <div class="border rounded-2 p-2 overflow-auto"
                     style="max-height:320px;"
                     id="<?= h($uid) ?>-rel-list">
                    <?php foreach ($rows as $row): ?>
                        <label class="d-flex align-items-start gap-2 py-1 px-1 rounded-2 <?= $row['editable'] ? '' : 'opacity-50' ?>"
                               style="cursor:<?= $row['editable'] ? 'pointer' : 'not-allowed' ?>;"
                               data-rel-row
                               data-tag-name="<?= h(strtolower($row['name'])) ?>"
                               <?= $row['editable'] ? '' : 'title="' . h($isGalaxy
                                   ? __('You do not have permission to modify this cluster.')
                                   : __('You do not have permission to modify this tag.')) . '"' ?>>
                            <input type="checkbox"
                                   class="form-check-input mt-1 flex-shrink-0"
                                   value="<?= (int)$row['connector_id'] ?>"
                                   data-rel-check
                                   <?= $row['editable'] ? '' : 'disabled' ?>>
                            <span><?= $badge($row) ?></span>
                        </label>
                    <?php endforeach; ?>

                    <div class="text-center text-muted py-3 small d-none" data-rel-noresult>
                        <i class="fas fa-search me-1 opacity-50"></i>
                        <?= $isGalaxy
                            ? __('No clusters match your search.')
                            : __('No tags match your search.') ?>
                    </div>
                </div>

            <?php endif; ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => $accent,
        'hint' => __('Saving a relationship does not unpublish the event.'),
        'submit' => ($mayModify && !empty($rows)) ? [
            /* An inner span because the label swaps with the picker: an empty
               relationship removes rather than applies. */
            'labelHtml' => '<span>' . h(__('Apply Relationship')) . '</span>',
            'icon' => 'fas fa-save',
            'id' => $uid . '-rel-save',
            'type' => 'button',
            'disabled' => true,
        ] : false,
    ]) ?>

</div>

<script>
    var postUrl    = <?= json_encode(h($saveUrl)) ?>;
    var uid        = <?= json_encode($uid) ?>;
    var reloadHook = <?= json_encode($reloadHook) ?>;

    var selectEl = document.getElementById(uid + '-rel-select');
    var listEl   = document.getElementById(uid + '-rel-list');
    var searchEl = document.getElementById(uid + '-rel-search');
    var countEl  = document.getElementById(uid + '-rel-count');
    var saveBtn  = document.getElementById(uid + '-rel-save');
    var allBtn   = document.getElementById(uid + '-rel-all');
    var noneBtn  = document.getElementById(uid + '-rel-none');

    /*
     * The relationship is free text with suggestions: initTomSelect() binds
     * select.tom-select with create:false, which would close the vocabulary to
     * the object-relationship table — the stock modal's "custom" option is
     * exactly this, minus the second input.
     */
    if (selectEl && !selectEl.tomselect && typeof TomSelect !== 'undefined') {
        var picker = new TomSelect(selectEl, {
            create: true,
            persist: false,
            createOnBlur: true,
            allowEmptyOption: true,
            maxOptions: null,
            placeholder: <?= json_encode(__('Pick a relationship…')) ?>,
            render: {
                option: function (data, escape) {
                    if (!data.desc) {
                        return '<div>' + escape(data.text) + '</div>';
                    }
                    return '<div><div>' + escape(data.text) + '</div>'
                         + '<div class="small text-muted">' + escape(data.desc) + '</div></div>';
                }
            }
        });
        /* A <select> selects its first option by itself, and allowEmptyOption
           makes the empty one a real item — so the modal would open already
           holding "no relationship", which is a write. Start on the
           placeholder instead and let that entry be a deliberate pick. */
        picker.clear(true);
    }

    function relationship() {
        if (!selectEl) { return ''; }
        var value = selectEl.tomselect ? selectEl.tomselect.getValue() : selectEl.value;
        return (value || '').trim();
    }

    /*
     * Nothing picked yet and "— No relationship —" picked on purpose both read
     * as an empty value, and only the second one may save: the first is how the
     * modal opens. TomSelect holds the empty entry as an item like any other,
     * so the difference is whether it holds one at all.
     */
    function hasChoice() {
        if (!selectEl) { return false; }
        if (selectEl.tomselect) { return selectEl.tomselect.items.length > 0; }
        return selectEl.selectedIndex >= 0;
    }

    function checkboxes() {
        return listEl ? Array.prototype.slice.call(
            listEl.querySelectorAll('[data-rel-check]')) : [];
    }

    function checkedIds() {
        return checkboxes()
            .filter(function (c) { return c.checked; })
            .map(function (c) { return parseInt(c.value, 10); });
    }

    /* The button says which of the two writes is about to happen, and the
       count line says what the disabled one is still waiting for. */
    function refresh() {
        var picked = checkedIds().length;
        var chosen = hasChoice();
        if (countEl) {
            if (picked === 0) {
                countEl.textContent = <?= json_encode($isGalaxy
                    ? __('No cluster selected') : __('No tag selected')) ?>;
            } else if (!chosen) {
                countEl.textContent = picked + ' ' + <?= json_encode(__('selected')) ?>
                    + ' · ' + <?= json_encode(__('pick a relationship')) ?>;
            } else {
                countEl.textContent = picked + ' ' + <?= json_encode(__('selected')) ?>;
            }
        }
        if (saveBtn) {
            saveBtn.disabled = picked === 0 || !chosen;
            var label = saveBtn.querySelector('span');
            if (label) {
                label.textContent = (chosen && relationship() === '')
                    ? <?= json_encode(__('Remove Relationship')) ?>
                    : <?= json_encode(__('Apply Relationship')) ?>;
            }
        }
    }

    if (listEl) {
        listEl.addEventListener('change', function (e) {
            if (e.target && e.target.hasAttribute('data-rel-check')) { refresh(); }
        });
    }
    if (selectEl) {
        selectEl.addEventListener('change', refresh);
    }
    if (allBtn) {
        allBtn.addEventListener('click', function () {
            /* Only what the filter currently shows, so "select all" never
               reaches a tag the user cannot see. */
            checkboxes().forEach(function (c) {
                var row = c.closest('[data-rel-row]');
                if (!c.disabled && row && !row.classList.contains('d-none')) {
                    c.checked = true;
                }
            });
            refresh();
        });
    }
    if (noneBtn) {
        noneBtn.addEventListener('click', function () {
            checkboxes().forEach(function (c) { c.checked = false; });
            refresh();
        });
    }

    /* ─── Filter ─── */
    if (searchEl && listEl) {
        searchEl.addEventListener('input', function () {
            var q = searchEl.value.toLowerCase().trim();
            var rows = listEl.querySelectorAll('[data-rel-row]');
            var noResult = listEl.querySelector('[data-rel-noresult]');
            var visible = 0;
            rows.forEach(function (row) {
                var name = row.getAttribute('data-tag-name') || '';
                var show = q === '' || name.indexOf(q) !== -1;
                row.classList.toggle('d-none', !show);
                if (show) { visible++; }
            });
            if (noResult) {
                noResult.classList.toggle('d-none', !(rows.length > 0 && visible === 0));
            }
        });
    }

    /* ─── Save ─── */
    if (saveBtn) {
        saveBtn.addEventListener('click', function () {
            var ids = checkedIds();
            if (!ids.length) { return; }
            saveBtn.disabled = true;

            fetch(postUrl, {
                method: 'POST',
                headers: {
                    'Content-Type':     'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept':           'application/json',
                    'X-CSRF-Token':     getCsrfToken()
                },
                body: JSON.stringify({
                    relationship: relationship(),
                    tag_connector_ids: ids
                })
            })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (data.saved) {
                    var modal = document.getElementById('mainModal');
                    if (modal) {
                        (bootstrap.Modal.getInstance(modal)
                            || new bootstrap.Modal(modal)).hide();
                    }
                    showToast(data.success || <?= json_encode(__('Relationship updated.')) ?>, 'success');
                    /* An event-view card has a reload hook; a row in the
                       attribute or object index has the index behind it. */
                    var cardReload = reloadHook ? window[reloadHook + uid] : null;
                    if (typeof cardReload === 'function') {
                        cardReload();
                    } else {
                        reloadEventViewIndexTab();
                    }
                } else {
                    showToast(data.errors || <?= json_encode(__('Failed to update the relationship.')) ?>, 'danger');
                    saveBtn.disabled = false;
                }
            })
            .catch(function () {
                showToast(<?= json_encode(__('Request failed — please try again.')) ?>, 'danger');
                saveBtn.disabled = false;
            });
        });
    }

    refresh();
</script>
