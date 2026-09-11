<?php

$reportData  = $data['EventReport'] ?? [];
$reportId    = (int)($reportData['id'] ?? 0);
$eventId     = (int)($reportData['event_id'] ?? ($data['Event']['id'] ?? 0));
$content     = $reportData['content'] ?? '';
$editable    = !empty($canEdit);
$pdfModule   = !empty($isDownloadAsPDFModuleAvailable);

/*
 * The rendering rules, in the order the menu lists them. The keys are the ones
 * MispReportMarkdown knows (RENDERING_RULES in js/misp-report-markdown.js) —
 * a key with no counterpart there is a switch that toggles nothing.
 */
$renderingRules = [
    ['key' => 'attribute',        'icon' => 'misp-icon misp-icon-attribute misp-simple', 'label' => __('Attribute')],
    ['key' => 'attribute-picture', 'icon' => 'fas fa-images',                            'label' => __('Attribute picture')],
    ['key' => 'object',           'icon' => 'misp-icon misp-icon-object misp-simple',    'label' => __('Object')],
    ['key' => 'object-attribute', 'icon' => 'misp-icon misp-icon-object misp-simple',    'label' => __('Object Attribute')],
    ['key' => 'tag',              'icon' => 'misp-icon misp-icon-tag misp-simple',       'label' => __('Tag')],
    ['key' => 'galaxymatrix',     'icon' => 'misp-icon misp-icon-galaxy misp-simple',    'label' => __('Galaxy matrix')],
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

$menuItems = [
    // ── Download ──────────────────────────────────────────────────
    ['type' => 'header', 'icon' => 'fas fa-download', 'label' => __('Download')],
    [
        'type'       => 'item',
        'onclick'    => "erDownloadMarkdown('pdf-module', event)",
        'icon'       => 'fas fa-file-pdf',
        'disabled'   => !$pdfModule,
        'label_html' => $pdfModule
            ? h(__('Download PDF (via misp-module)'))
            : '<span class="text-decoration-line-through">'
              . h(__('Download PDF (via misp-module)'))
              . '</span> <i class="fas fa-info-circle ms-1 text-muted" data-bs-toggle="tooltip" title="'
              . h(__('Module `convert_markdown_to_pdf` not available'))
              . '"></i>',
    ],
    [
        'type'    => 'item',
        'onclick' => "erDownloadMarkdown('pdf-print', event)",
        'icon'    => 'fas fa-print',
        'label'   => __('Download PDF (via print)'),
    ],
    [
        'type'    => 'item',
        'onclick' => "erDownloadMarkdown('text', event)",
        'icon'    => 'fab fa-markdown',
        'label'   => __('Download Markdown'),
    ],
    [
        'type'    => 'item',
        'onclick' => "erDownloadMarkdown('text-gfm', event)",
        'icon'    => 'fab fa-markdown',
        'label'   => __('Download GFM simplified format'),
        'title'   => __('Replace custom syntax by a valid one'),
    ],
    // ── Parsing rules ─────────────────────────────────────────────
    ['type' => 'divider'],
    ['type' => 'header', 'icon' => 'fas fa-cog', 'label' => __('Markdown parsing rules')],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRule('image', event)",
        'icon'     => 'fas fa-image',
        'label'    => __('Image parsing'),
        'badge_id' => 'er-rule-image',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRule('link', event)",
        'icon'     => 'fas fa-link',
        'label'    => __('Link parsing'),
        'badge_id' => 'er-rule-link',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRule('misp', event)",
        'icon'     => 'fas fa-fingerprint',
        'label'    => __('MISP Elements'),
        'badge_id' => 'er-rule-misp',
    ],
    // ── Rendering rules ─────────────────────────────────────────────
    ['type' => 'divider'],
    ['type' => 'header', 'icon' => 'fas fa-cog', 'label' => __('Markdown rendering rules')],
];

foreach ($renderingRules as $rule) {
    $menuItems[] = [
        'type'     => 'toggle',
        'onclick'  => sprintf("erToggleRenderingRule('%s', event)", $rule['key']),
        'icon'     => $rule['icon'],
        'label'    => $rule['label'],
        'badge_id' => 'er-render-' . $rule['key'],
    ];
}

$menuItems = array_merge($menuItems, [
    // ── Templating ─────────────────────────────────────────────
    ['type' => 'divider'],
    ['type' => 'header', 'icon' => 'fas fa-screwdriver-wrench', 'label' => __('Templating')],
    [
        'type'   => 'item',
        'url'    => $baseurl . '/EventReportTemplateVariables/index/',
        'target' => '_blank',
        'icon'   => 'fas fa-screwdriver',
        'label'  => __('Configure Template variables'),
    ],
    // ── LLM ─────────────────────────────────────────────
    ['type' => 'divider'],
    ['type' => 'header', 'icon' => 'fas fa-robot', 'label' => __('LLM')],
    [
        'type'    => 'item',
        'onclick' => "erSendToLLM(event)",
        'icon'    => 'fas fa-robot',
        'label'   => __('Send report to LLM'),
    ],
]);

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

        <div class="d-flex align-items-center gap-3">

            <?php if ($editable): ?>
            <!-- SAVE -->
            <button type="button"
                    id="er-save-btn"
                    class="btn btn-sm btn-primary"
                    onclick="erSaveContent()"
                    title="Ctrl+S">
                <i class="fas fa-save me-1"></i><?= __('Save') ?>
            </button>
            <?php endif; ?>

            <!-- HELP -->
            <button type="button"
                    class="btn btn-sm btn-outline-secondary"
                    data-bs-toggle="modal"
                    data-bs-target="#er-help-modal"
                    title="<?= __('Markdown help') ?>">
                <i class="fas fa-circle-question me-1"></i><?= __('Help') ?>
            </button>

            <!-- MENU DROPDOWN -->
            <div class="dropdown">
                <button type="button"
                        class="btn btn-sm btn-outline-secondary dropdown-toggle"
                        data-bs-toggle="dropdown"
                        aria-expanded="false">
                    <i class="fas fa-ellipsis-h me-1"></i><?= __('Menu') ?>
                </button>

                <ul class="dropdown-menu dropdown-menu-end" style="min-width:240px;">
                    <?php foreach ($menuItems as $item): ?>
                        <?php if ($item['type'] === 'header'): ?>
                            <li>
                                <h6 class="dropdown-header">
                                    <i class="<?= h($item['icon']) ?> me-1"></i>
                                    <?= h($item['label']) ?>
                                </h6>
                            </li>

                        <?php elseif ($item['type'] === 'divider'): ?>
                            <li><hr class="dropdown-divider"></li>

                        <?php elseif ($item['type'] === 'item'): ?>
                            <li>
                                <a class="dropdown-item <?= !empty($item['disabled']) ? 'disabled text-muted' : '' ?>"
                                   href="<?= !empty($item['url']) && empty($item['disabled']) ? h($item['url']) : '#' ?>"
                                   <?= !empty($item['target']) ? 'target="' . h($item['target']) . '"' : '' ?>
                                   <?= !empty($item['title']) ? 'title="' . h($item['title']) . '"' : '' ?>
                                   <?= !empty($item['onclick']) ? 'onclick="' . h($item['onclick']) . '"' : '' ?>>
                                    <i class="<?= h($item['icon']) ?> me-2"></i>
                                    <?php if (!empty($item['label_html'])): ?>
                                        <?= $item['label_html'] ?>
                                    <?php else: ?>
                                        <?= h($item['label'] ?? '') ?>
                                    <?php endif; ?>
                                </a>
                            </li>

                        <?php elseif ($item['type'] === 'toggle'): ?>
                            <li>
                                <a class="dropdown-item d-flex align-items-center gap-2"
                                   href="#"
                                   onclick="<?= h($item['onclick'] ?? '') ?>">
                                    <i class="<?= h($item['icon']) ?>"></i>
                                    <?= h($item['label'] ?? '') ?>
                                    <span id="<?= h($item['badge_id']) ?>"
                                          class="badge bg-success ms-auto">
                                        <?= __('enabled') ?>
                                    </span>
                                </a>
                            </li>

                        <?php endif; ?>
                    <?php endforeach; ?>
                </ul>
            </div>

        </div>
    </div>

    <!-- ─── SPLIT SCREEN ─────────────────────────────────────── -->
    <div class="row g-0" style="min-height:70vh;">

        <!-- EDITOR -->
        <div class="col-lg-6 d-flex flex-column border-end">
            <div class="px-2 py-1 border-bottom bg-body-tertiary small text-muted fw-semibold">
                <i class="fas fa-pen me-1"></i><?= __('Edit') ?>
            </div>
            <!-- The colours are a <pre> under a textarea whose own text is
                 transparent; both are filled by MispReportMarkdown. -->
            <div class="ov-raw-wrap">
                <pre id="er-editor-layer" class="ov-raw-layer" aria-hidden="true"></pre>
                <textarea
                    id="er-editor"
                    class="ov-raw-input"
                    spellcheck="false"
                    <?= $editable ? '' : 'readonly' ?>
                ><?= h($content) ?></textarea>
            </div>
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

<!-- ─── LLM CONFIRMATION MODAL ───────────────────────────────── -->
<div class="modal fade"
     id="er-llm-modal"
     tabindex="-1"
     aria-labelledby="er-llm-modal-label"
     aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">

            <div class="modal-header">
                <h5 class="modal-title d-flex align-items-center gap-2"
                    id="er-llm-modal-label">
                    <i class="fas fa-robot text-primary"></i>
                    <?= __('Send to LLM') ?>
                </h5>
                <button type="button"
                        class="btn-close"
                        data-bs-dismiss="modal"
                        aria-label="<?= __('Close') ?>">
                </button>
            </div>

            <div class="modal-body">
                <p class="mb-0">
                    <?= __('Send this report to the LLM for processing?') ?>
                </p>
                <p class="text-muted small mt-1 mb-0">
                    <i class="fas fa-clock me-1"></i>
                    <?= __('This may take a moment.') ?>
                </p>
            </div>

            <div class="modal-footer gap-2">
                <button type="button"
                        class="btn btn-outline-secondary"
                        data-bs-dismiss="modal">
                    <?= __('Cancel') ?>
                </button>
                <button type="button"
                        id="er-llm-confirm-btn"
                        class="btn btn-primary"
                        onclick="erConfirmLLM()">
                    <i class="fas fa-robot me-1"></i>
                    <?= __('Confirm') ?>
                </button>
            </div>

        </div>
    </div>
</div>

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

    /* ── Unsaved badge ───────────────────────────────────────── */
    function erUpdateUnsavedBadge() {
        var editor = document.getElementById('er-editor');
        var badge  = document.getElementById('er-unsaved-badge');
        if (!editor || !badge) { return; }
        badge.style.display = (editor.value !== erOriginalContent) ? '' : 'none';
    }

    /* ── Live preview (debounced 150 ms) ─────────────────────── */
    function erScheduleRender() {
        clearTimeout(erRenderTimer);
        erRenderTimer = setTimeout(erRenderLivePreview, 150);
    }

    function erRenderLivePreview() {
        var editor  = document.getElementById('er-editor');
        var preview = document.getElementById('er-live-preview');
        if (!editor || !preview || !erRenderer) { return; }
        erRenderer.render(editor.value, preview);
    }

    /* ── Parsing rules toggle ────────────────────────────────── */
    window.erToggleRule = function (rulename, e) {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        if (!erRenderer) { return; }
        erRenderer.toggleParsingRule(rulename);
        erUpdateRuleUI();
        erRenderLivePreview();
    };

    /* ── Rendering rules toggle ──────────────────────────────── */
    window.erToggleRenderingRule = function (rulename, e) {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        if (!erRenderer) { return; }
        if (!erRenderer.setRenderingRule(rulename, !erRenderer.getRenderingRule(rulename))) {
            return;
        }
        erUpdateRuleUI();
        erRenderLivePreview();
    };

    function erSetBadge(id, enabled) {
        var badge = document.getElementById(id);
        if (!badge) { return; }
        badge.textContent = enabled
            ? <?= json_encode(__('enabled')) ?>
            : <?= json_encode(__('disabled')) ?>;
        badge.className = 'badge ms-auto ' + (enabled ? 'bg-success' : 'bg-secondary');
    }

    function erUpdateRuleUI() {
        if (!erRenderer) { return; }
        ['image', 'link', 'misp'].forEach(function (rule) {
            erSetBadge('er-rule-' + rule, erRenderer.getParsingRule(rule));
        });
        erRenderer.renderingRuleNames().forEach(function (rule) {
            erSetBadge('er-render-' + rule, erRenderer.getRenderingRule(rule));
        });
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
    window.erSaveContent = async function () {
        if (!erEditable) { return; }

        var btn    = document.getElementById('er-save-btn');
        var editor = document.getElementById('er-editor');
        if (!btn || !editor) { return; }

        var editUrl = baseurl + '/eventReports/edit/' + erReportId;

        btn.disabled   = true;
        btn.innerHTML  = '<span class="spinner-border spinner-border-sm me-1" role="status"></span><?= __('Saving…') ?>';

        try {
            /* Fetch edit form to obtain CSRF tokens and existing fields */
            var formResp = await fetch(editUrl, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            var formHtml = await formResp.text();

            var parser = new DOMParser();
            var doc    = parser.parseFromString(formHtml, 'text/html');
            var form   = doc.querySelector('form');
            if (!form) { throw new Error('Edit form not found'); }

            var formData = new FormData(form);
            formData.set('data[EventReport][content]', editor.value);

            var postResp = await fetch(form.action || editUrl, {
                method: 'POST',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                body: new URLSearchParams(formData)
            });

            var result = await postResp.json();

            if (result.saved !== false) {
                showToast(result.message || '<?= __('Content saved') ?>', 'success');
                erOriginalContent = editor.value;
                erUpdateUnsavedBadge();

                document.dispatchEvent(new CustomEvent('misp:report-saved', {
                    detail: { reportId: erReportId, content: editor.value }
                }));
            } else {
                showToast(result.message || '<?= __('Save failed') ?>', 'danger');
            }

        } catch (err) {
            showToast('<?= __('Save failed') ?>: ' + err.message, 'danger');
        } finally {
            btn.disabled  = false;
            btn.innerHTML = '<i class="fas fa-save me-1"></i><?= __('Save') ?>';
        }
    };

    /* ── Send to LLM ─────────────────────────────────────────── */

    /* Step 1 — open the BS5 confirmation modal */
    window.erSendToLLM = function (e) {
        if (e) { e.preventDefault(); }
        var modal = new bootstrap.Modal(document.getElementById('er-llm-modal'));
        modal.show();
    };

    /* Step 2 — user clicked "Confirm" inside the modal */
    window.erConfirmLLM = async function () {
        /* Close the confirmation modal */
        var modalEl = document.getElementById('er-llm-modal');
        var modal   = bootstrap.Modal.getInstance(modalEl);
        if (modal) { modal.hide(); }

        var confirmBtn = document.getElementById('er-llm-confirm-btn');
        if (confirmBtn) {
            confirmBtn.disabled  = true;
            confirmBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-1" role="status"></span><?= __('Sending…') ?>';
        }

        showToast('<?= __('Sending to LLM… please wait.') ?>', 'primary');

        var url = baseurl + '/eventReports/sendToLLM/' + erReportId;

        try {
            /* GET the Overmind sendToLLM view to obtain the CSRF token */
            var formResp = await fetch(url, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            if (!formResp.ok) { throw new Error('HTTP ' + formResp.status); }

            var formHtml = await formResp.text();
            var parser   = new DOMParser();
            var doc      = parser.parseFromString(formHtml, 'text/html');
            var form     = doc.querySelector('form');
            if (!form) { throw new Error('<?= __('CSRF form not found in response') ?>'); }

            /* POST back with CSRF tokens */
            var postResp = await fetch(form.action || url, {
                method: 'POST',
                headers: { 'X-Requested-With': 'XMLHttpRequest' },
                body: new URLSearchParams(new FormData(form))
            });

            var result = await postResp.json();

            if (result.saved !== false) {
                showToast(result.message || '<?= __('Report sent to LLM successfully') ?>', 'success');
                setTimeout(function () { window.location.reload(); }, 1500);
            } else {
                var errDetail = result.errors || result.message || '<?= __('Failed to send to LLM') ?>';
                showToast(errDetail, 'danger');
            }

        } catch (err) {
            showToast('<?= __('Failed to send to LLM') ?>: ' + err.message, 'danger');
        } finally {
            if (confirmBtn) {
                confirmBtn.disabled  = false;
                confirmBtn.innerHTML = '<i class="fas fa-robot me-1"></i><?= __('Confirm') ?>';
            }
        }
    };

})();
</script>
