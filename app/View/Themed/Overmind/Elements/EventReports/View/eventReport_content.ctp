<?php

$reportData  = $data['EventReport'] ?? [];
$reportId    = (int)($reportData['id'] ?? 0);
$eventId     = (int)($reportData['event_id'] ?? ($data['Event']['id'] ?? 0));
$content     = $reportData['content'] ?? '';
$editable    = !empty($canEdit);
$pdfModule   = !empty($isDownloadAsPDFModuleAvailable);
$live        = $editable && empty($reportData['deleted']);

/*
 * The parsing and rendering rules, as the Display menu lists them. The keys
 * are the ones MispReportMarkdown knows (setParsingRule / RENDERING_RULES in
 * js/misp-report-markdown.js) — a key with no counterpart there is a switch
 * that toggles nothing.
 */
$parsingRules = [
    ['key' => 'image', 'icon' => 'fas fa-image',       'label' => __('Images')],
    ['key' => 'link',  'icon' => 'fas fa-link',        'label' => __('Links')],
    ['key' => 'misp',  'icon' => 'fas fa-fingerprint', 'label' => __('MISP elements')],
];
$renderingRules = [
    ['key' => 'attribute',         'icon' => 'misp-icon misp-icon-attribute misp-simple', 'label' => __('Attribute')],
    ['key' => 'attribute-picture', 'icon' => 'fas fa-images',                             'label' => __('Attribute picture')],
    ['key' => 'object',            'icon' => 'misp-icon misp-icon-object misp-simple',    'label' => __('Object')],
    ['key' => 'object-attribute',  'icon' => 'misp-icon misp-icon-object misp-simple',    'label' => __('Object attribute')],
    ['key' => 'tag',               'icon' => 'misp-icon misp-icon-tag misp-simple',       'label' => __('Tag')],
    ['key' => 'galaxymatrix',      'icon' => 'misp-icon misp-icon-galaxy misp-simple',    'label' => __('Galaxy matrix')],
];

/*
 * The writing toolbar, the stock editor's #top-bar. The action names are
 * MispReportMarkdown's (ACTIONS in bindSourceEditing) — the module owns what
 * each one does to the text, this array only says how it is drawn.
 */
$toolbarGroups = [
    [
        ['action' => 'bold',          'icon' => 'fas fa-bold',          'label' => __('Bold'),          'keys' => 'Ctrl+B'],
        ['action' => 'italic',        'icon' => 'fas fa-italic',        'label' => __('Italic'),        'keys' => 'Ctrl+I'],
        ['action' => 'heading',       'icon' => 'fas fa-heading',       'label' => __('Heading'),       'keys' => 'Ctrl+H'],
        ['action' => 'strikethrough', 'icon' => 'fas fa-strikethrough', 'label' => __('Strikethrough')],
    ],
    [
        ['action' => 'list-ul', 'icon' => 'fas fa-list-ul', 'label' => __('Unordered list')],
        ['action' => 'list-ol', 'icon' => 'fas fa-list-ol', 'label' => __('Ordered list')],
    ],
    [
        ['action' => 'quote', 'icon' => 'fas fa-quote-left', 'label' => __('Quote')],
        ['action' => 'code',  'icon' => 'fas fa-code',       'label' => __('Code')],
        ['action' => 'table', 'icon' => 'fas fa-table',      'label' => __('Table')],
    ],
    [
        ['action' => 'attribute',         'icon' => 'misp-icon misp-icon-attribute misp-simple', 'label' => __('Attribute'), 'keys' => 'Ctrl+M'],
        ['action' => 'attribute-picture', 'icon' => 'fas fa-images',                             'label' => __('Attribute picture')],
        ['action' => 'object',            'icon' => 'misp-icon misp-icon-object misp-simple',    'label' => __('Object')],
        ['action' => 'tag',               'icon' => 'misp-icon misp-icon-tag misp-simple',       'label' => __('Tag')],
        ['action' => 'galaxymatrix',      'icon' => 'misp-icon misp-icon-galaxy misp-simple',    'label' => __('Galaxy matrix')],
    ],
];

$downloadItems = [
    [
        'onclick'  => "erDownloadMarkdown('pdf-module', event)",
        'icon'     => 'fas fa-file-pdf',
        'label'    => __('PDF (via misp-module)'),
        'disabled' => !$pdfModule,
        'note'     => $pdfModule ? '' : __('needs the convert_markdown_to_pdf module'),
    ],
    ['onclick' => "erDownloadMarkdown('pdf-print', event)", 'icon' => 'fas fa-print', 'label' => __('PDF (via print)')],
    ['onclick' => "erDownloadMarkdown('text', event)", 'icon' => 'fab fa-markdown', 'label' => __('Markdown')],
    [
        'onclick' => "erDownloadMarkdown('text-gfm', event)",
        'icon'    => 'fab fa-markdown',
        'label'   => __('GFM simplified format'),
        'title'   => __('Replace custom syntax by a valid one'),
    ],
];

/* Tools: each section only when the user may run what is in it. */
$toolSections = [];
if ($live && $this->Acl->canAccess('eventReports', 'extractFromReport')) {
    $toolSections[] = [
        'label' => __('Extract entities'),
        'items' => [
            [
                'onclick' => 'erStartManualExtraction(event)',
                'icon'    => 'fas fa-highlighter',
                'label'   => __('Manual extraction'),
                'title'   => __('Review what the report holds and pick, occurrence by occurrence, what becomes an attribute or a reference'),
            ],
            [
                'onclick' => 'erOpenAutomaticExtraction(event)',
                'icon'    => 'fas fa-wand-magic-sparkles',
                'label'   => __('Automatic extraction'),
                'title'   => __('Create every attribute the freetext tools find and reference them in the report'),
            ],
        ],
    ];
}
// The AI module from the report page: a summary put on top of the report (a
// previous AI summary is replaced), or indicators proposed from this report
// only and reviewed in the modal before they are added to the event.
$aiItems = [];
$aiOn = $live && Configure::read('Plugin.AI_services_enable');
if ($aiOn && $this->Acl->canAccess('eventReports', 'aiExtractIndicators')) {
    $url = $baseurl . '/eventReports/aiExtractIndicators/' . $reportId;
    $aiItems[] = [
        'url'     => $url,
        'onclick' => "event.preventDefault(); openModal('" . $url . "', 'md');",
        'icon'    => 'fas fa-magnifying-glass',
        'label'   => __('Extract indicators'),
        'title'   => __('The AI module reads this report and proposes attributes and objects, reviewed before they are added'),
    ];
}
if ($aiOn && $this->Acl->canAccess('eventReports', 'aiSummarize')) {
    $url = $baseurl . '/eventReports/aiSummarize/' . $reportId;
    $aiItems[] = [
        'url'     => $url,
        'onclick' => "event.preventDefault(); openModal('" . $url . "', 'md');",
        'icon'    => 'fas fa-file-lines',
        'label'   => __('Summarise report'),
        'title'   => __('The AI module puts its summary on top of the report; a previous AI summary is replaced'),
    ];
}
if ($aiItems) {
    $toolSections[] = ['label' => __('AI'), 'items' => $aiItems];
}
$toolSections[] = [
    'label' => __('Templating'),
    'items' => [[
        'url'    => $baseurl . '/EventReportTemplateVariables/index/',
        'target' => '_blank',
        'icon'   => 'fas fa-screwdriver-wrench',
        'label'  => __('Template variables'),
        'title'  => __('Configure the {{ variables }} a report can use (opens in a new tab)'),
    ]],
];

$extractionStrings = [
    'title' => __('Manual extraction'),
    'hint' => __('Pick a row, then untick the occurrences to leave alone in the preview.'),
    'close' => __('Close'),
    'working' => __('Working…'),
    'extracting' => __('Extracting entities…'),
    'applying' => __('Creating the attribute…'),
    'saving' => __('Saving the report…'),
    'extractFailed' => __('Could not extract entities from the report:'),
    'applyFailed' => __('Could not apply the suggestion:'),
    'applied' => __('Suggestion applied'),
    'noForm' => __('The suggestion form could not be read.'),
    'noneTicked' => __('No occurrence is ticked in the preview.'),
    'toggle' => __('Click to include or leave out this occurrence'),
    'notRendered' => __('%s occurrence(s) sit in code or another construct the preview does not draw: they are left as they are.'),
    'tab_replacement' => __('Data replacement'),
    'tab_context' => __('Context replacement'),
    'tab_extraction' => __('Data extraction'),
    'tip_replacement' => __('Text already present as an attribute of the event: reference that attribute'),
    'tip_context' => __('Text naming a tag or a galaxy cluster: reference it'),
    'tip_extraction' => __('Values the freetext tools recognise: create the attribute and reference it'),
    'empty_replacement' => __('No raw text matches an attribute of the event.'),
    'empty_context' => __('No raw text matches a tag or a galaxy cluster.'),
    'empty_extraction' => __('The freetext tools found nothing to extract.'),
    'value' => __('Value'),
    'type' => __('Type'),
    'category' => __('Category'),
    'existingAttribute' => __('Existing attribute'),
    'existingContext' => __('Existing context'),
    'occurrences' => __('Occurrences'),
    'previous' => __('Previous occurrence'),
    'next' => __('Next occurrence'),
    'extractSave' => __('Extract & save'),
    'replaceSave' => __('Replace & save'),
];

echo $this->element('genericElements/assetLoader', ['js' => ['overmind-report-extraction']]);
?>

<div class="card shadow-sm mb-3" id="er-content-card">

    <!-- ─── CARD HEADER ───────────────────────────────────────── -->
    <div class="card-header d-flex align-items-center justify-content-between flex-wrap gap-2 py-2">

        <div class="d-flex align-items-center gap-2">
            <span id="er-unsaved-badge"
                  class="badge bg-warning text-dark ms-1"
                  style="display:none; font-size:0.7rem;">
                <?= __('Unsaved changes') ?>
            </span>

            <?php if ($editable): ?>
            <!-- WRITING TOOLBAR -->
            <div id="er-toolbar" class="ov-md-toolbar" role="toolbar"
                 aria-label="<?= __('Formatting') ?>">
                <?php foreach ($toolbarGroups as $i => $group): ?>
                    <?php if ($i): ?><span class="ov-md-tool-sep"></span><?php endif; ?>
                    <?php foreach ($group as $tool): ?>
                        <button type="button"
                                class="ov-md-tool"
                                data-md-action="<?= h($tool['action']) ?>"
                                title="<?= h($tool['label'] . (empty($tool['keys']) ? '' : ' (' . $tool['keys'] . ')')) ?>"
                                aria-label="<?= h($tool['label']) ?>">
                            <i class="<?= h($tool['icon']) ?>"></i>
                        </button>
                    <?php endforeach; ?>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
        </div>

        <div class="d-flex align-items-center gap-2">

            <?php if ($editable): ?>
            <button type="button"
                    id="er-save-btn"
                    class="btn btn-sm btn-primary"
                    onclick="erSaveContent()"
                    title="Ctrl+S">
                <i class="fas fa-save me-1"></i><?= __('Save') ?>
            </button>
            <?php endif; ?>

            <button type="button"
                    class="btn btn-sm btn-outline-secondary"
                    data-bs-toggle="modal"
                    data-bs-target="#er-help-modal"
                    title="<?= __('Markdown help') ?>"
                    aria-label="<?= __('Markdown help') ?>">
                <i class="fas fa-circle-question"></i>
            </button>

            <!-- DOWNLOAD -->
            <div class="dropdown">
                <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle"
                        data-bs-toggle="dropdown" aria-expanded="false" title="<?= __('Download') ?>">
                    <i class="fas fa-download me-1"></i><?= __('Download') ?>
                </button>
                <ul class="dropdown-menu dropdown-menu-end">
                    <?php foreach ($downloadItems as $item): ?>
                    <li>
                        <a class="dropdown-item d-flex align-items-center gap-2 <?= !empty($item['disabled']) ? 'disabled' : '' ?>"
                           href="#"
                           <?= !empty($item['title']) ? 'title="' . h($item['title']) . '"' : '' ?>
                           onclick="<?= h($item['onclick']) ?>">
                            <i class="<?= h($item['icon']) ?> fa-fw text-body-secondary"></i>
                            <span>
                                <?= h($item['label']) ?>
                                <?php if (!empty($item['note'])): ?>
                                    <small class="d-block"><?= h($item['note']) ?></small>
                                <?php endif; ?>
                            </span>
                        </a>
                    </li>
                    <?php endforeach; ?>
                </ul>
            </div>

            <!-- DISPLAY: parsing and rendering rules -->
            <div class="dropdown">
                <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle"
                        data-bs-toggle="dropdown" data-bs-auto-close="outside" aria-expanded="false">
                    <i class="fas fa-eye me-1"></i><?= __('Display') ?>
                </button>
                <div class="dropdown-menu dropdown-menu-end p-3 small" style="min-width:31rem;" id="er-rules">
                    <div class="row g-3">
                        <div class="col-6">
                            <div class="text-uppercase text-body-secondary fw-semibold mb-2" style="font-size:.7rem;">
                                <?= __('Parsing') ?>
                            </div>
                            <?php foreach ($parsingRules as $rule): ?>
                            <div class="form-check form-switch mb-1">
                                <input class="form-check-input" type="checkbox" role="switch" checked
                                       id="er-rule-<?= h($rule['key']) ?>" data-er-parsing="<?= h($rule['key']) ?>">
                                <label class="form-check-label" for="er-rule-<?= h($rule['key']) ?>">
                                    <i class="<?= h($rule['icon']) ?> fa-fw me-1 text-body-secondary"></i><?= h($rule['label']) ?>
                                </label>
                            </div>
                            <?php endforeach; ?>
                        </div>
                        <div class="col-6 border-start">
                            <div class="text-uppercase text-body-secondary fw-semibold mb-2" style="font-size:.7rem;">
                                <?= __('Rendering') ?>
                            </div>
                            <?php foreach ($renderingRules as $rule): ?>
                            <div class="form-check form-switch mb-1">
                                <input class="form-check-input" type="checkbox" role="switch" checked
                                       id="er-render-<?= h($rule['key']) ?>" data-er-rendering="<?= h($rule['key']) ?>">
                                <label class="form-check-label" for="er-render-<?= h($rule['key']) ?>">
                                    <i class="<?= h($rule['icon']) ?> fa-fw me-1 text-body-secondary"></i><?= h($rule['label']) ?>
                                </label>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <div class="text-body-secondary mt-2" style="font-size:.7rem;">
                        <?= __('Off: the element keeps its value but is drawn as plain text.') ?>
                    </div>
                </div>
            </div>

            <!-- TOOLS -->
            <div class="dropdown">
                <button type="button" class="btn btn-sm btn-outline-secondary dropdown-toggle"
                        data-bs-toggle="dropdown" aria-expanded="false">
                    <i class="fas fa-toolbox me-1"></i><?= __('Tools') ?>
                </button>
                <ul class="dropdown-menu dropdown-menu-end" style="min-width:15rem;">
                    <?php foreach ($toolSections as $i => $section): ?>
                        <?php if ($i): ?><li><hr class="dropdown-divider"></li><?php endif; ?>
                        <li><h6 class="dropdown-header"><?= h($section['label']) ?></h6></li>
                        <?php foreach ($section['items'] as $item): ?>
                        <li>
                            <a class="dropdown-item d-flex align-items-center gap-2"
                               href="<?= h($item['url'] ?? '#') ?>"
                               <?= !empty($item['target']) ? 'target="' . h($item['target']) . '"' : '' ?>
                               <?= !empty($item['title']) ? 'title="' . h($item['title']) . '"' : '' ?>
                               <?= !empty($item['onclick']) ? 'onclick="' . h($item['onclick']) . '"' : '' ?>>
                                <i class="<?= h($item['icon']) ?> fa-fw text-body-secondary"></i><?= h($item['label']) ?>
                                <?php if (!empty($item['target'])): ?>
                                    <i class="fas fa-arrow-up-right-from-square ms-auto text-body-secondary" style="font-size:.7rem;"></i>
                                <?php endif; ?>
                            </a>
                        </li>
                        <?php endforeach; ?>
                    <?php endforeach; ?>
                </ul>
            </div>

        </div>
    </div>

    <!-- ─── SPLIT SCREEN ─────────────────────────────────────── -->
    <div class="row g-0" style="min-height:70vh;">

        <!-- EDITOR (or the manual extraction panel in its place) -->
        <div class="col-lg-6 d-flex flex-column border-end">
            <div class="px-2 py-1 border-bottom bg-body-tertiary small text-muted fw-semibold" data-er-editor-part>
                <i class="fas fa-pen me-1"></i><?= __('Edit') ?>
            </div>
            <!-- The colours are a <pre> under a textarea whose own text is
                 transparent; both are filled by MispReportMarkdown. -->
            <div class="ov-raw-wrap" data-er-editor-part>
                <pre id="er-editor-layer" class="ov-raw-layer" aria-hidden="true"></pre>
                <textarea
                    id="er-editor"
                    class="ov-raw-input"
                    spellcheck="false"
                    <?= $editable ? '' : 'readonly' ?>
                ><?= h($content) ?></textarea>
            </div>
            <div id="er-extraction-panel" class="position-relative d-flex flex-column flex-grow-1 d-none"
                 style="min-height:68vh;"></div>
        </div>

        <!-- LIVE PREVIEW -->
        <div class="col-lg-6 d-flex flex-column">
            <div class="px-2 py-1 border-bottom bg-body-tertiary small text-muted fw-semibold">
                <i class="fas fa-eye me-1"></i><?= __('Preview') ?>
            </div>
            <div id="er-live-preview"
                 class="markdown-preview-body p-3 flex-grow-1 overflow-auto"
                 style="height:100%; min-height:68vh;"></div>
        </div>

    </div>

</div>

<?= $this->element('EventReports/View/eventReport_help_modal') ?>

<script type="application/json" id="er-extraction-strings"><?= json_encode($extractionStrings, JSON_HEX_TAG | JSON_HEX_AMP) ?></script>

<script>
(function () {
    'use strict';

    /* ── Constants ───────────────────────────────────────────── */
    var erReportId        = <?= json_encode($reportId) ?>;
    var erEventId         = <?= json_encode($eventId) ?>;
    var erEditable        = <?= $editable ? 'true' : 'false' ?>;
    var erOriginalContent = <?= json_encode($content) ?>;
    /* {{ name }} substitutions — the renderer normalises MISP's row shape. */
    var erTemplateVars    = <?= json_encode($templateVariables ?? []) ?>;
    var erRenderer        = null;
    var erRenderTimer     = null;
    var L = <?= json_encode([
        'saveFirst' => __('Save or discard your changes first: the extraction works on the saved report.'),
        'saved' => __('Content saved'),
        'saveFailed' => __('Save failed'),
        'saving' => __('Saving…'),
        'save' => __('Save'),
    ], JSON_HEX_TAG | JSON_HEX_AMP) ?>;

    /* ── Bootstrap ───────────────────────────────────────────── */
    document.addEventListener('DOMContentLoaded', function () {
        var editor  = document.getElementById('er-editor');
        var preview = document.getElementById('er-live-preview');
        if (!editor) { return; }

        editor.addEventListener('input', function () {
            erUpdateUnsavedBadge();
            erScheduleRender();
        });
        editor.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                if (erEditable) { erSaveContent(); }
            }
        });

        var rules = document.getElementById('er-rules');
        if (rules) {
            rules.addEventListener('change', erOnRuleChange);
        }

        if (!window.MispReportMarkdown) { return; }

        var layer = document.getElementById('er-editor-layer');
        if (layer) { window.MispReportMarkdown.bindSourceHighlight(editor, layer); }

        if (!preview) { return; }
        erRenderer = window.MispReportMarkdown.create({
            reportId: erReportId,
            eventId: erEventId,
            templateVariables: erTemplateVars,
            invalidMessage: <?= json_encode(__('invalid scope or id')) ?>,
            onProxyError: function () {
                showToast(
                    <?= json_encode(__('Could not load the event\'s MISP elements: attributes, objects and tags will not be rendered.')) ?>,
                    'warning'
                );
            }
        });

        // The shortcuts the Help modal lists, and the Ctrl+Space suggestion
        if (erEditable) {
            window.MispReportMarkdown.bindSourceEditing(
                editor, erRenderer, document.getElementById('er-toolbar')
            );
        }

        erRenderer.ready.then(function () {
            erRenderLivePreview();
            erUpdateRuleUI();
        });
        erUpdateRuleUI();
    });

    function erIsDirty() {
        var editor = document.getElementById('er-editor');
        return !!editor && editor.value !== erOriginalContent;
    }

    /* ── Unsaved badge ───────────────────────────────────────── */
    function erUpdateUnsavedBadge() {
        var badge = document.getElementById('er-unsaved-badge');
        if (!badge) { return; }
        badge.style.display = erIsDirty() ? '' : 'none';
    }

    /* ── Live preview (debounced 150 ms) ─────────────────────── */
    function erScheduleRender() {
        clearTimeout(erRenderTimer);
        erRenderTimer = setTimeout(erRenderLivePreview, 150);
    }

    /* While the manual extraction is open the preview shows its marked copy. */
    function erRenderLivePreview() {
        if (window.OvReportExtraction && OvReportExtraction.isActive()) {
            OvReportExtraction.refresh();
            return;
        }
        var editor  = document.getElementById('er-editor');
        var preview = document.getElementById('er-live-preview');
        if (!editor || !preview || !erRenderer) { return; }
        erRenderer.render(editor.value, preview);
    }

    /* ── Parsing and rendering rules (the Display menu) ──────── */
    function erOnRuleChange(e) {
        var input = e.target;
        if (!erRenderer || !input.matches('input[type="checkbox"]')) { return; }
        if (input.dataset.erParsing) {
            erRenderer.setParsingRule(input.dataset.erParsing, input.checked);
        } else if (input.dataset.erRendering) {
            erRenderer.setRenderingRule(input.dataset.erRendering, input.checked);
        }
        erUpdateRuleUI();
        erRenderLivePreview();
    }

    function erUpdateRuleUI() {
        if (!erRenderer) { return; }
        document.querySelectorAll('[data-er-parsing]').forEach(function (input) {
            input.checked = erRenderer.getParsingRule(input.dataset.erParsing);
        });
        document.querySelectorAll('[data-er-rendering]').forEach(function (input) {
            input.checked = erRenderer.getRenderingRule(input.dataset.erRendering);
        });
    }

    /* ── Extraction (the Tools menu) ─────────────────────────── */
    window.erStartManualExtraction = function (e) {
        if (e) { e.preventDefault(); }
        if (!erRenderer || !window.OvReportExtraction) { return; }
        if (erIsDirty()) {
            showToast(L.saveFirst, 'warning');
            return;
        }
        var toolbar = document.getElementById('er-toolbar');
        if (toolbar) { toolbar.classList.add('pe-none', 'opacity-50'); }
        OvReportExtraction.start({
            reportId: erReportId,
            panel: document.getElementById('er-extraction-panel'),
            editorParts: Array.prototype.slice.call(document.querySelectorAll('[data-er-editor-part]')),
            preview: document.getElementById('er-live-preview'),
            renderer: erRenderer,
            strings: JSON.parse(document.getElementById('er-extraction-strings').textContent),
            getContent: function () { return document.getElementById('er-editor').value; },
            save: erPersist,
            onSaved: erAdoptSavedContent,
            onClose: function () {
                if (toolbar) { toolbar.classList.remove('pe-none', 'opacity-50'); }
                erRenderLivePreview();
            }
        });
    };

    window.erOpenAutomaticExtraction = function (e) {
        if (e) { e.preventDefault(); }
        if (erIsDirty()) {
            showToast(L.saveFirst, 'warning');
            return;
        }
        openModal(baseurl + '/eventReports/extractAllFromReport/' + erReportId, 'md');
    };

    /* ── Download ────────────────────────────────────────────── */
    window.erDownloadMarkdown = function (type, e) {
        if (e) { e.preventDefault(); }

        var editor = document.getElementById('er-editor');
        if (!editor) { return; }
        var raw      = editor.value;
        var filename = 'event-report-' + new Date().getTime() + '.md';

        if (type === 'pdf-print') {
            erPrintPreview();
            return;
        }

        if (type === 'pdf-module') {
            window.location.href = baseurl + '/eventReports/downloadAsPDF/' + erReportId;
            return;
        }

        /* text / text-gfm — Blob download */
        var fileContent = raw;
        if (type === 'text-gfm' && erRenderer) {
            fileContent = erRenderer.toGfm(raw);
        }
        var blob = new Blob([fileContent], { type: 'text/markdown;charset=utf-8' });
        var url  = URL.createObjectURL(blob);
        var a    = document.createElement('a');
        a.href     = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    };

    /**
     * Print window. The report's own stylesheets are linked rather
     * than re-declared
     */
    function erPrintPreview() {
        var preview = document.getElementById('er-live-preview');
        if (!preview) { return; }

        var version = <?= json_encode($queryVersion ?? '') ?>;
        var suffix  = version ? ('?v=' + encodeURIComponent(version)) : '';
        var sheets  = ['bootstrap5-custom.min', 'mainOvermind', 'fontawesome7.min'];
        var links   = sheets.map(function (name) {
            return '<link rel="stylesheet" href="'
                + baseurl + '/css/' + name + '.css' + suffix + '">';
        }).join('');

        var win = window.open('', '_blank', 'width=900,height=700');
        if (!win) {
            showToast(
                <?= json_encode(__('The print window was blocked by the browser.')) ?>,
                'danger'
            );
            return;
        }
        var printed = false;
        function printOnce() {
            if (printed) { return; }
            printed = true;
            win.focus();
            win.print();
        }
        /* Listen before writing: document.close() can fire load right away,
           and a stylesheet that never answers must not leave the window
           sitting there unprinted either. */
        win.addEventListener('load', printOnce);
        win.document.write(
            '<!DOCTYPE html><html><head><meta charset="utf-8">'
            + '<title>' + <?= json_encode(__('Event Report')) ?> + ' ' + erReportId + '</title>'
            + links
            + '<style>body{padding:2rem;max-width:900px;margin:auto;}</style>'
            + '</head><body><div class="markdown-preview-body">'
            + preview.innerHTML
            + '</div></body></html>'
        );
        win.document.close();
        setTimeout(printOnce, 1500);
    }

    /* ── Save ────────────────────────────────────────────────── */

    /* The text the server now holds becomes the editor's baseline. */
    function erAdoptSavedContent(content) {
        var editor = document.getElementById('er-editor');
        if (editor && editor.value !== content) {
            editor.value = content;
            editor.dispatchEvent(new Event('input'));
        }
        erOriginalContent = content;
        erUpdateUnsavedBadge();
        document.dispatchEvent(new CustomEvent('misp:report-saved', {
            detail: { reportId: erReportId, content: content }
        }));
    }

    /* Saves `content` through the edit form (its tokens come with it);
       resolves to whether the server took it. */
    async function erPersist(content) {
        var btn     = document.getElementById('er-save-btn');
        var editUrl = baseurl + '/eventReports/edit/' + erReportId;

        if (btn) {
            btn.disabled  = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span>' + L.saving;
        }
        try {
            /* Fetch edit form to obtain CSRF tokens and existing fields */
            var formResp = await fetch(editUrl, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            var formHtml = await formResp.text();

            var doc  = new DOMParser().parseFromString(formHtml, 'text/html');
            var form = doc.querySelector('form');
            if (!form) { throw new Error('Edit form not found'); }

            var formData = new FormData(form);
            formData.set('data[EventReport][content]', content);

            var postResp = await fetch(form.action || editUrl, {
                method: 'POST',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                body: new URLSearchParams(formData)
            });
            var result = await postResp.json();

            if (result.saved !== false) {
                showToast(result.message || L.saved, 'success');
                erAdoptSavedContent(content);
                return true;
            }
            showToast(result.message || L.saveFailed, 'danger');
            return false;
        } catch (err) {
            showToast(L.saveFailed + ': ' + err.message, 'danger');
            return false;
        } finally {
            if (btn) {
                btn.disabled  = false;
                btn.innerHTML = '<i class="fas fa-save me-1"></i>' + L.save;
            }
        }
    }

    window.erSaveContent = function () {
        if (!erEditable) { return Promise.resolve(false); }
        var editor = document.getElementById('er-editor');
        return editor ? erPersist(editor.value) : Promise.resolve(false);
    };

})();
</script>
