<?php
/*
 * events/restSearchExport (GET) — pick a format for the selected events.
 *
 * Reached from the events index mass-action toolbar, which hands the selected
 * ids over in the URL (multiSelectItems() in mispOvermind.js). Nothing is
 * posted: the Export button calls the global redirectToExportResult(), which
 * reads the format off #EventReturnFormat and the ids off #PromptForm's
 * data-idlist, then navigates to restSearchExport/<ids>/<format>. Both of
 * those hooks have to keep their ids.
 *
 * Available vars: $idList, $exportFormats. Globals: $baseurl.
 */

$idList = $idList ?? [];
$count = count($idList);

$formatGlyphs = [];
foreach ($exportFormats as $key => $label) {
    $formatGlyphs[(string)$key] = $this->ExportFormat->get($key);
}

echo $this->Form->create('Event', [
    'id' => 'PromptForm',
    'url' => $baseurl . '/events/restSearchExport',
    'class' => 'm-0',
    'novalidate' => true,
    'data-idlist' => json_encode($idList),
]);
?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'accent' => 'event',
    'eyebrow' => __('Events'),
    'title' => __('Export Events'),
    'description' => __('Download the selected events in one document.'),
    'titleIcon' => 'fas fa-file-export',
    'icon' => 'misp-icon misp-icon-event misp-simple',
    /* Raw HTML by contract, so the count is escaped here. */
    'titleBadge' => $count === 0
        ? ''
        : '<span class="badge rounded-pill text-bg-light border">'
            . h(__n('%s event', '%s events', $count, $count)) . '</span>',
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <div class="w-100 px-2">
            <?= $this->element('genericElementsBS5/Forms/section_label', [
                'accent' => 'event',
                'label' => __('Export Format'),
                'required' => true,
                'for' => 'EventReturnFormat',
            ]) ?>
            <?= $this->Form->select('returnFormat', $exportFormats, [
                'id' => 'EventReturnFormat',
                'class' => 'form-select tom-select',
                'empty' => false,
            ]) ?>
            <div id="EventReturnFormatGlyphs" class="d-none"
                 data-glyphs="<?= h(json_encode($formatGlyphs, JSON_FORCE_OBJECT)) ?>"></div>
            <?= $this->element('genericElementsBS5/Forms/field_hint', [
                'text' => __('Lossy formats keep only what they can express — MISP JSON and MISP XML keep everything.'),
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'accent' => 'event',
        'cancel' => ['label' => __('Cancel'), 'icon' => 'fas fa-xmark'],
        'submit' => [
            'label' => __('Export'),
            'icon' => 'fas fa-file-export',
            'type' => 'button',
            'id' => 'PromptYesButton',
            'disabled' => $count === 0,
            'attrs' => ['onclick' => 'redirectToExportResult();'],
        ],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var select = document.getElementById('EventReturnFormat');
    var carrier = document.getElementById('EventReturnFormatGlyphs');
    if (!select || !carrier || typeof TomSelect !== 'function') { return; }

    var glyphs = {};
    try {
        glyphs = JSON.parse(carrier.dataset.glyphs || '{}');
    } catch (e) { /* the plain select still works */ }

    function row(data, small) {
        var wrap = document.createElement('div');
        wrap.className = 'd-flex align-items-center '
            + (small ? 'gap-2' : 'gap-2 py-1');

        var meta = glyphs[String(data.value)];
        if (meta) {
            var tile = document.createElement('span');
            tile.className = 'ex-icon flex-shrink-0';
            tile.style.setProperty('--h', meta.hue);
            if (small) {
                tile.style.width = '1.4rem';
                tile.style.height = '1.4rem';
                tile.style.fontSize = '.7rem';
            }
            var icon = document.createElement('i');
            icon.className = meta.icon;
            tile.appendChild(icon);
            wrap.appendChild(tile);
        }

        var label = document.createElement('span');
        /* textContent: a format label never reaches the DOM as markup. */
        label.textContent = data.text;
        wrap.appendChild(label);
        return wrap;
    }

    /* initTomSelect() would have made a plain one out of the .tom-select
       class; build it here first so the renderers are the ones that stick. */
    if (!select.tomselect) {
        new TomSelect(select, {
            create: false,
            persist: false,
            render: {
                option: function (data) { return row(data, false); },
                item: function (data) { return row(data, true); }
            }
        });
    }
})();
</script>