<?php

$reportData  = $data['EventReport'] ?? [];
$reportId    = (int)($reportData['id'] ?? 0);
$eventId     = (int)($reportData['event_id'] ?? ($data['Event']['id'] ?? 0));
$content     = $reportData['content'] ?? '';
$editable    = !empty($canEdit);
$pdfModule   = !empty($isDownloadAsPDFModuleAvailable);
$writable    = $editable && empty($reportData['deleted']);

/*
 * The preview switches. The parsing keys are MispReportMarkdown's
 * parsingRules, the rendering keys its RENDERING_RULES — a key with no
 * counterpart there is a switch that toggles nothing.
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
$ruleCount = count($parsingRules) + count($renderingRules);

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

$downloads = [
    [
        'type'     => 'pdf-module',
        'icon'     => 'fas fa-file-pdf',
        'label'    => __('PDF'),
        'title'    => $pdfModule
            ? __('Download PDF (via misp-module)')
            : __('Download PDF (via misp-module): module `convert_markdown_to_pdf` not available'),
        'disabled' => !$pdfModule,
    ],
    ['type' => 'pdf-print', 'icon' => 'fas fa-print',   'label' => __('Print'),    'title' => __('Download PDF (via print)')],
    ['type' => 'text',      'icon' => 'fab fa-markdown', 'label' => __('Markdown'), 'title' => __('Download Markdown')],
    [
        'type'  => 'text-gfm',
        'icon'  => 'fab fa-markdown',
        'label' => __('GFM'),
        'title' => __('Download GFM simplified format: custom syntax replaced by a valid one'),
    ],
];

$canExtract = $writable
    && $this->Acl->canAccess('eventReports', 'extractFromReport')
    && $this->Acl->canAccess('eventReports', 'replaceSuggestionInReport');
$autoExtractUrl = ($writable && $this->Acl->canAccess('eventReports', 'extractAllFromReport'))
    ? $baseurl . '/eventReports/extractAllFromReport/' . $reportId
    : null;

$aiOn = $writable && Configure::read('Plugin.AI_services_enable');
// The AI module puts its summary on top of the report (a previous AI summary
// is replaced).
$aiSummarizeUrl = ($aiOn && $this->Acl->canAccess('eventReports', 'aiSummarize'))
    ? $baseurl . '/eventReports/aiSummarize/' . $reportId
    : null;
// Only this report is sent; the answer is reviewed in the modal before it is
// added to the event.
$aiExtractUrl = ($aiOn && $this->Acl->canAccess('eventReports', 'aiExtractIndicators'))
    ? $baseurl . '/eventReports/aiExtractIndicators/' . $reportId
    : null;

/* The Actions menu below the download tiles, one section per family. */
$menuSections = [];
$extractItems = [];
if ($canExtract) {
    $extractItems[] = [
        'onclick' => 'erManualExtraction(event)',
        'icon'    => 'fas fa-highlighter',
        'label'   => __('Manual extraction'),
        'title'   => __('Review each value found in the report and link or create it one at a time'),
    ];
}
if ($autoExtractUrl !== null) {
    $extractItems[] = [
        'onclick' => 'erAutoExtraction(event)',
        'icon'    => 'fas fa-wand-magic-sparkles',
        'label'   => __('Automatic extraction'),
        'title'   => __('Create and link every value found in the report at once'),
    ];
}
if ($extractItems) {
    $menuSections[] = ['label' => __('Extract entities'), 'items' => $extractItems];
}
$aiItems = [];
if ($aiSummarizeUrl !== null) {
    $aiItems[] = [
        'url'     => $aiSummarizeUrl,
        'onclick' => "event.preventDefault(); openModal('" . $aiSummarizeUrl . "', 'md');",
        'icon'    => 'fas fa-file-lines',
        'label'   => __('Summarise report'),
        'title'   => __('The AI module puts its summary on top of the report; a previous AI summary is replaced'),
    ];
}
if ($aiExtractUrl !== null) {
    $aiItems[] = [
        'url'     => $aiExtractUrl,
        'onclick' => "event.preventDefault(); openModal('" . $aiExtractUrl . "', 'md');",
        'icon'    => 'fas fa-magnifying-glass',
        'label'   => __('Extract indicators'),
        'title'   => __('The AI module reads this report and proposes attributes and objects, reviewed before they are added'),
    ];
}
if ($aiItems) {
    $menuSections[] = ['label' => __('AI'), 'items' => $aiItems];
}
$menuSections[] = ['label' => null, 'items' => [[
    'url'    => $baseurl . '/EventReportTemplateVariables/index/',
    'target' => '_blank',
    'icon'   => 'fas fa-screwdriver-wrench',
    'label'  => __('Template variables'),
    'title'  => __('Configure template variables (opens a new tab)'),
    'trail'  => 'fas fa-arrow-up-right-from-square',
]]];

$ruleSwitch = function (array $rule, $group) {
    $id = 'er-rule-' . $group . '-' . $rule['key'];
    return sprintf(
        '<label class="ov-md-rule form-switch" for="%s"><i class="%s"></i><span>%s</span>'
        . '<input class="form-check-input" type="checkbox" role="switch" id="%s" data-er-rule="%s" value="%s" checked></label>',
        h($id),
        h($rule['icon']),
        h($rule['label']),
        h($id),
        h($group),
        h($rule['key'])
    );
};

$helpTool = sprintf(
    '<button type="button" class="ov-md-tool" data-bs-toggle="modal" data-bs-target="#er-help-modal" title="%s" aria-label="%s"><i class="fas fa-circle-question"></i></button>',
    h(__('Markdown help')),
    h(__('Markdown help'))
);
?>

<div class="card shadow-sm mb-3 ov-md-editor" id="er-content-card">

    <div class="card-header ov-md-head">

        <div class="ov-md-head-tools">
            <!-- WRITING TOOLBAR -->
            <div id="er-toolbar" class="ov-md-toolbar" role="toolbar"
                 aria-label="<?= __('Formatting') ?>">
                <?php if ($editable): ?>
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
                    <span class="ov-md-tool-sep"></span>
                <?php endif; ?>
                <?= $helpTool ?>
            </div>
        </div>

        <div class="ov-md-head-actions">
            <?php if ($editable): ?>
            <button type="button"
                    id="er-save-btn"
                    class="ov-md-save is-clean"
                    onclick="erSaveContent()"
                    disabled
                    title="<?= __('Save (Ctrl+S)') ?>"></button>
            <?php endif; ?>

            <div class="dropdown">
                <button type="button"
                        class="ov-md-btn"
                        data-bs-toggle="dropdown"
                        aria-expanded="false">
                    <i class="fas fa-ellipsis"></i><?= __('Actions') ?><i class="fas fa-chevron-down ov-md-chev"></i>
                </button>
                <div class="dropdown-menu dropdown-menu-end ov-md-menu ov-md-actions">
                    <span class="ov-md-menu-h"><?= __('Download') ?></span>
                    <div class="ov-md-dl">
                        <?php foreach ($downloads as $download): ?>
                            <button type="button"
                                    class="dropdown-item ov-md-dl-tile"
                                    title="<?= h($download['title']) ?>"
                                    <?= empty($download['disabled']) ? '' : 'disabled' ?>
                                    onclick="erDownloadMarkdown('<?= h($download['type']) ?>', event)">
                                <i class="<?= h($download['icon']) ?>"></i><?= h($download['label']) ?>
                            </button>
                        <?php endforeach; ?>
                    </div>
                    <?php foreach ($menuSections as $section): ?>
                        <hr class="dropdown-divider">
                        <?php if (!empty($section['label'])): ?>
                            <span class="ov-md-menu-h"><?= h($section['label']) ?></span>
                        <?php endif; ?>
                        <?php foreach ($section['items'] as $item): ?>
                            <a class="dropdown-item"
                               href="<?= h($item['url'] ?? '#') ?>"
                               <?= !empty($item['target']) ? 'target="' . h($item['target']) . '" rel="noopener"' : '' ?>
                               <?= !empty($item['title']) ? 'title="' . h($item['title']) . '"' : '' ?>
                               <?= !empty($item['onclick']) ? 'onclick="' . h($item['onclick']) . '"' : '' ?>>
                                <i class="<?= h($item['icon']) ?>"></i><?= h($item['label']) ?>
                                <?php if (!empty($item['trail'])): ?>
                                    <small class="ov-md-menu-trail"><i class="<?= h($item['trail']) ?>"></i></small>
                                <?php endif; ?>
                            </a>
                        <?php endforeach; ?>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>

        <?php if ($canExtract): ?>
        <!-- Shown instead of the two blocks above while extracting -->
        <div class="ov-md-x-mode">
            <i class="fas fa-highlighter"></i>
            <span class="fw-semibold"><?= __('Manual extraction') ?></span>
            <span class="ov-md-x-mode-note"><?= __('Each change is saved as you apply it.') ?></span>
        </div>
        <button type="button" class="ov-md-btn ov-md-x-close" onclick="erCloseExtraction()">
            <i class="fas fa-xmark"></i><?= __('Close extraction') ?>
        </button>
        <?php endif; ?>
    </div>

    <!-- ─── SPLIT SCREEN ─────────────────────────────────────── -->
    <div class="row g-0" style="min-height:70vh;">

        <!-- EDITOR -->
        <div class="col-lg-6 d-flex flex-column border-end">
            <div class="ov-md-pane-bar ov-md-source-part">
                <span><i class="fas fa-pen"></i><?= __('Edit') ?></span>
            </div>
            <!-- The colours are a <pre> under a textarea whose own text is
                 transparent; both are filled by MispReportMarkdown. -->
            <div class="ov-raw-wrap ov-md-source-part">
                <pre id="er-editor-layer" class="ov-raw-layer" aria-hidden="true"></pre>
                <textarea
                    id="er-editor"
                    class="ov-raw-input"
                    spellcheck="false"
                    <?= $editable ? '' : 'readonly' ?>
                ><?= h($content) ?></textarea>
            </div>

            <?php if ($canExtract): ?>
            <div class="ov-md-x" id="er-extract" hidden>
                <nav class="ov-view-tabs is-inline ov-md-x-tabs" role="tablist"
                     aria-label="<?= __('What was found') ?>">
                    <button type="button" class="nav-view" role="tab" data-x-tab="new"
                            title="<?= __('Values the freetext import recognises, not in the event yet') ?>">
                        <i class="fas fa-wand-magic-sparkles"></i><?= __('New attributes') ?>
                        <span class="ov-tab-count" data-x-count>0</span>
                    </button>
                    <button type="button" class="nav-view" role="tab" data-x-tab="existing"
                            title="<?= __('Values of the event\'s attributes the report does not reference yet') ?>">
                        <i class="misp-icon misp-icon-attribute misp-simple"></i><?= __('Event attributes') ?>
                        <span class="ov-tab-count" data-x-count>0</span>
                    </button>
                    <button type="button" class="nav-view" role="tab" data-x-tab="context"
                            title="<?= __('Tag and galaxy cluster names found in the report') ?>">
                        <i class="fas fa-tags"></i><?= __('Tags & galaxies') ?>
                        <span class="ov-tab-count" data-x-count>0</span>
                    </button>
                </nav>
                <p class="ov-md-x-intro">
                    <?= __('Pick a value: its occurrences are ticked in the preview. Untick those that should stay as text, then apply.') ?>
                </p>
                <div class="ov-md-x-list" data-x-list role="listbox"
                     aria-label="<?= __('Values found in the report') ?>"></div>
            </div>
            <?php endif; ?>
        </div>

        <!-- LIVE PREVIEW -->
        <div class="col-lg-6 d-flex flex-column">
            <div class="ov-md-pane-bar">
                <span><i class="fas fa-eye"></i><?= __('Preview') ?></span>
                <div class="dropdown">
                    <button type="button"
                            class="ov-md-pane-btn"
                            data-bs-toggle="dropdown"
                            data-bs-auto-close="outside"
                            aria-expanded="false"
                            title="<?= __('Markdown parsing and rendering rules') ?>">
                        <i class="fas fa-sliders"></i><?= __('Rendering') ?>
                        <span class="ov-md-rule-count" id="er-rule-count"><?= $ruleCount ?>/<?= $ruleCount ?></span>
                        <i class="fas fa-chevron-down ov-md-chev"></i>
                    </button>
                    <div class="dropdown-menu dropdown-menu-end ov-md-menu ov-md-rules">
                        <span class="ov-md-menu-h"><?= __('Parsing') ?></span>
                        <?php foreach ($parsingRules as $rule): ?>
                            <?= $ruleSwitch($rule, 'parse') ?>
                        <?php endforeach; ?>
                        <span class="ov-md-menu-h"><?= __('Rendering') ?></span>
                        <div class="ov-md-rule-grid">
                            <?php foreach ($renderingRules as $rule): ?>
                                <?= $ruleSwitch($rule, 'render') ?>
                            <?php endforeach; ?>
                        </div>
                        <div class="ov-md-menu-foot">
                            <span><?= __('Applies to this preview only') ?></span>
                            <button type="button" class="btn btn-link btn-sm p-0" onclick="erResetRules()"><?= __('Reset') ?></button>
                        </div>
                    </div>
                </div>
            </div>
            <div id="er-live-preview"
                 class="markdown-preview-body p-3 flex-grow-1 overflow-auto"
                 style="height:100%; min-height:68vh;"></div>
        </div>

    </div>

</div>

<?= $this->element('EventReports/View/eventReport_help_modal') ?>

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
    var erAutoExtractUrl  = <?= json_encode($autoExtractUrl) ?>;
    var erCanExtract      = <?= $canExtract ? 'true' : 'false' ?>;
    var erRenderer        = null;
    var erRenderTimer     = null;
    var erExtraction      = null;
    var erSaving          = false;

    var L = <?= json_encode([
        'save' => __('Save'),
        'saved' => __('Saved'),
        'saving' => __('Saving…'),
        'unsaved' => __('Unsaved changes (Ctrl+S)'),
        'contentSaved' => __('Content saved'),
        'saveFailed' => __('Save failed'),
        'savedFirst' => __('Your changes were saved first: extraction reads the saved report.'),
        'x' => [
            'loading' => __('Extracting entities…'),
            'loadFailed' => __('Could not extract entities from the report.'),
            'failed' => __('The report could not be updated.'),
            'type' => __('Type'),
            'category' => __('Category'),
            'attribute' => __('Attribute'),
            'tag' => __('Tag'),
            'prev' => __('Previous occurrence'),
            'next' => __('Next occurrence'),
            'position' => __('%i of %n'),
            'ticked' => __('%i of %n ticked'),
            'occurrences' => __('Occurrences in the report'),
            'otherTypes' => __('+%n other types'),
            'attributesMatch' => __('%n attributes match'),
            'tagsMatch' => __('%n tags match'),
            'applyNew' => __('Create attribute'),
            'applyExisting' => __('Link to attribute'),
            'applyContext' => __('Replace with tag'),
            'notShown' => __('%n occurrence(s) sit in code or a link and stay as text.'),
            'emptyNew' => __('No new value found in this report.'),
            'emptyExisting' => __('Every event attribute found in the report is already referenced.'),
            'emptyContext' => __('No tag or galaxy name found in this report.'),
            'created' => __('Attribute created and linked'),
            'linked' => __('Occurrences linked to the attribute'),
            'tagged' => __('Occurrences replaced with the tag'),
        ],
    ], JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;

    /* ── Bootstrap ───────────────────────────────────────────── */
    document.addEventListener('DOMContentLoaded', function () {
        var editor  = document.getElementById('er-editor');
        var preview = document.getElementById('er-live-preview');
        if (!editor) { return; }

        editor.addEventListener('input', function () {
            erUpdateSaveState();
            erScheduleRender();
        });
        editor.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key === 's') {
                e.preventDefault();
                if (erEditable) { erSaveContent(); }
            }
        });
        erUpdateSaveState();

        document.querySelectorAll('#er-content-card [data-er-rule]').forEach(function (input) {
            input.addEventListener('change', function () {
                erSetRule(input.getAttribute('data-er-rule'), input.value, input.checked);
            });
        });

        /* An extraction elsewhere (the automatic one, from its modal) rewrote
           the saved report: take its content. */
        document.addEventListener('misp:report-saved', function (event) {
            var detail = event.detail || {};
            if (Number(detail.reportId) !== Number(erReportId) || detail.source === 'editor') { return; }
            erTakeSavedContent(detail.content, !!detail.elementsChanged);
        });

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

        var panel = document.getElementById('er-extract');
        if (erCanExtract && panel && window.MispReportExtraction) {
            erExtraction = window.MispReportExtraction.create({
                reportId: erReportId,
                renderer: erRenderer,
                panel: panel,
                preview: preview,
                labels: L.x,
                getContent: function () { return editor.value; },
                save: erSaveReport,
                onSaved: function (content) {
                    erTakeSavedContent(content, false);
                    erAnnounceSaved(content, true);
                },
                onClose: function () {
                    document.getElementById('er-content-card').classList.remove('is-extracting');
                    erRenderLivePreview();
                }
            });
        }

        erRenderer.ready.then(function () {
            erRenderLivePreview();
            erUpdateRuleUI();
        });
        erUpdateRuleUI();
    });

    /* ── Save state ──────────────────────────────────────────── */
    function erIsDirty() {
        var editor = document.getElementById('er-editor');
        return !!editor && editor.value !== erOriginalContent;
    }

    function erUpdateSaveState() {
        var btn = document.getElementById('er-save-btn');
        if (!btn) { return; }
        if (erSaving) {
            btn.className = 'ov-md-save is-saving';
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>' + L.saving;
            return;
        }
        var dirty = erIsDirty();
        btn.className = 'ov-md-save ' + (dirty ? 'is-dirty' : 'is-clean');
        btn.disabled = !dirty;
        btn.title = dirty ? L.unsaved : L.saved;
        btn.innerHTML = dirty
            ? '<span class="ov-md-save-dot" aria-hidden="true"></span><i class="fas fa-floppy-disk"></i>'
              + L.save + '<kbd class="ov-md-kbd">Ctrl S</kbd>'
            : '<i class="fas fa-check"></i>' + L.saved;
    }

    /* ── Live preview (debounced 150 ms) ─────────────────────── */
    function erScheduleRender() {
        clearTimeout(erRenderTimer);
        erRenderTimer = setTimeout(erRenderLivePreview, 150);
    }

    function erRenderLivePreview() {
        if (erExtraction && erExtraction.isOpen) {
            erExtraction._paint();
            return;
        }
        var editor  = document.getElementById('er-editor');
        var preview = document.getElementById('er-live-preview');
        if (!editor || !preview || !erRenderer) { return; }
        erRenderer.render(editor.value, preview);
    }

    /* ── Parsing and rendering rules ─────────────────────────── */
    function erSetRule(group, name, enabled) {
        if (!erRenderer) { return; }
        if (group === 'parse') {
            erRenderer.setParsingRule(name, enabled);
        } else {
            erRenderer.setRenderingRule(name, enabled);
        }
        erUpdateRuleUI();
        erRenderLivePreview();
    }

    window.erResetRules = function () {
        if (!erRenderer) { return; }
        ['image', 'link', 'misp'].forEach(function (rule) { erRenderer.setParsingRule(rule, true); });
        erRenderer.renderingRuleNames().forEach(function (rule) { erRenderer.setRenderingRule(rule, true); });
        erUpdateRuleUI();
        erRenderLivePreview();
    };

    function erUpdateRuleUI() {
        if (!erRenderer) { return; }
        var on = 0;
        var total = 0;
        document.querySelectorAll('#er-content-card [data-er-rule]').forEach(function (input) {
            var enabled = input.getAttribute('data-er-rule') === 'parse'
                ? erRenderer.getParsingRule(input.value)
                : erRenderer.getRenderingRule(input.value);
            input.checked = enabled;
            total++;
            if (enabled) { on++; }
        });
        var count = document.getElementById('er-rule-count');
        if (count) {
            count.textContent = on + '/' + total;
            count.classList.toggle('is-off', on < total);
        }
    }

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
        // Printed in Overmind's light palette whatever the page's theme is.
        var sheets  = ['themes/overmind.min', 'mainOvermind', 'fontawesome7.min'];
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

    /* Posts `content` through the edit form; resolves {ok, message}. */
    async function erSaveReport(content) {
        var editUrl = baseurl + '/eventReports/edit/' + erReportId;
        try {
            /* Fetch edit form to obtain CSRF tokens and existing fields */
            var formResp = await fetch(editUrl, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            var formHtml = await formResp.text();
            var form = new DOMParser().parseFromString(formHtml, 'text/html').querySelector('form');
            if (!form) { throw new Error('Edit form not found'); }

            var formData = new FormData(form);
            formData.set('data[EventReport][content]', content);

            var postResp = await fetch(form.action || editUrl, {
                method: 'POST',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                body: new URLSearchParams(formData)
            });
            var result = await postResp.json();
            return { ok: result.saved !== false, message: result.message };
        } catch (err) {
            return { ok: false, message: L.saveFailed + ': ' + err.message };
        }
    }

    function erAnnounceSaved(content, elementsChanged) {
        document.dispatchEvent(new CustomEvent('misp:report-saved', {
            detail: {
                reportId: erReportId,
                content: content,
                source: 'editor',
                elementsChanged: !!elementsChanged
            }
        }));
    }

    function erTakeSavedContent(content, reloadElements) {
        var editor = document.getElementById('er-editor');
        if (!editor || typeof content !== 'string') { return; }
        editor.value = content;
        erOriginalContent = content;
        editor.dispatchEvent(new Event('input'));
        if (reloadElements && erRenderer) {
            erRenderer.reload().then(erRenderLivePreview);
        }
    }

    window.erSaveContent = async function (quiet) {
        if (!erEditable || erSaving) { return false; }
        var editor = document.getElementById('er-editor');
        if (!editor) { return false; }

        var content = editor.value;
        erSaving = true;
        erUpdateSaveState();
        var result = await erSaveReport(content);
        erSaving = false;
        if (result.ok) {
            showToast(quiet ? L.savedFirst : (result.message || L.contentSaved), 'success');
            erOriginalContent = content;
            erAnnounceSaved(content, false);
        } else {
            showToast(result.message || L.saveFailed, 'danger');
        }
        erUpdateSaveState();
        return result.ok;
    };

    /* Extraction reads the saved report, so unsaved writing goes first. */
    async function erEnsureSaved() {
        if (!erIsDirty()) { return true; }
        return window.erSaveContent(true);
    }

    /* ── Extraction ──────────────────────────────────────────── */
    window.erManualExtraction = async function (e) {
        if (e) { e.preventDefault(); }
        if (!erExtraction || erExtraction.isOpen) { return; }
        if (!(await erEnsureSaved())) { return; }
        document.getElementById('er-content-card').classList.add('is-extracting');
        erExtraction.open();
    };

    window.erCloseExtraction = function () {
        if (erExtraction && erExtraction.isOpen) { erExtraction.close(); }
    };

    window.erAutoExtraction = async function (e) {
        if (e) { e.preventDefault(); }
        if (!erAutoExtractUrl) { return; }
        if (!(await erEnsureSaved())) { return; }
        openModal(erAutoExtractUrl, 'md');
    };

})();
</script>
