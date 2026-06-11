<?php

$reportData  = $data['EventReport'] ?? [];
$reportId    = (int)($reportData['id'] ?? 0);
$content     = $reportData['content'] ?? '';
$editable    = !empty($canEdit);
$pdfModule   = !empty($isDownloadAsPDFModuleAvailable);

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
        'onclick'  => "erToggleRule('link', event)",
        'icon'     => 'fas fa-link',
        'label'    => __('MISP Elements'),
        'badge_id' => 'er-rule-misp',
    ],
    // ── Rendering rules ─────────────────────────────────────────────
    ['type' => 'divider'],
    ['type' => 'header', 'icon' => 'fas fa-cog', 'label' => __('Markdown rendering rules')],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRenderingRule('attribute', event)",
        'icon'     => 'fas fa-inbox',
        'label'    => __('Attribute'),
        'badge_id' => 'er-render-attribute',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRenderingRule('attribute-picture', event)",
        'icon'     => 'fas fa-images',
        'label'    => __('Attribute picture'),
        'badge_id' => 'er-render-attribute-picture',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRenderingRule('object', event)",
        'icon'     => 'fas fa-cube',
        'label'    => __('Object'),
        'badge_id' => 'er-render-object',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRenderingRule('object-attribute', event)",
        'icon'     => 'fas fa-cubes',
        'label'    => __('Object Attribute'),
        'badge_id' => 'er-render-object-attribute',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRenderingRule('tag', event)",
        'icon'     => 'fas fa-tag',
        'label'    => __('Tag'),
        'badge_id' => 'er-render-tag',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRenderingRule('galaxymatrix', event)",
        'icon'     => 'fas fa-book-atlas',
        'label'    => __('Galaxy matrix'),
        'badge_id' => 'er-render-galaxymatrix',
    ],
    [
        'type'     => 'toggle',
        'onclick'  => "erToggleRenderingRule('suggestion', event)",
        'icon'     => 'fas fa-wand-magic-sparkles',
        'label'    => __('Suggestion'),
        'badge_id' => 'er-render-suggestion',
    ],
    // ── Templating ─────────────────────────────────────────────
    ['type' => 'divider'],
    ['type' => 'header', 'icon' => 'fas fa-screwdriver-wrench', 'label' => __('Templating')],
    [
        'type'    => 'item',
        'url'     => $baseurl . '/EventReportTemplateVariables/index/',
        'icon'    => 'fas fa-screwdriver',
        'label'   => __('Configure Template variables'),
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
];

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
        </div>

        <div class="d-flex align-items-center gap-2">

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
                                          class="badge bg-success">
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
            <textarea
                id="er-editor"
                class="form-control border-0 rounded-0 font-monospace flex-grow-1"
                style="height:100%; min-height:68vh; font-size:0.875rem; resize:none;"
                spellcheck="false"
                <?= $editable ? '' : 'readonly' ?>
            ><?= h($content) ?></textarea>
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

<!-- ─── LLM CONFIRMATION MODAL ───────────────────────────────── -->
<div class="modal fade"
     id="er-llm-modal"
     tabindex="-1"
     aria-labelledby="er-llm-modal-label"
     aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered modal-sm">
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

<style>
    .markdown-preview-body h1,
    .markdown-preview-body h2,
    .markdown-preview-body h3,
    .markdown-preview-body h4 { margin-top:1.2rem; margin-bottom:.4rem; font-weight:600; }
    .markdown-preview-body p  { margin-bottom:.75rem; }
    .markdown-preview-body pre { background:var(--bs-tertiary-bg); padding:.75rem 1rem; border-radius:.375rem; overflow-x:auto; }
    .markdown-preview-body code { font-size:.85em; }
    .markdown-preview-body blockquote { border-left:4px solid var(--bs-border-color); padding:.25rem .75rem; color:var(--bs-secondary-color); margin:.5rem 0; }
    .markdown-preview-body table { width:100%; border-collapse:collapse; margin-bottom:1rem; }
    .markdown-preview-body th,
    .markdown-preview-body td  { border:1px solid var(--bs-border-color); padding:.4rem .6rem; }
    .markdown-preview-body th  { background:var(--bs-tertiary-bg); font-weight:600; }
    .markdown-preview-body img { max-width:100%; height:auto; }
    .markdown-preview-body a   { color:var(--bs-link-color); }
    .markdown-preview-body hr  { border-color:var(--bs-border-color); }
</style>

<script>
(function () {
    'use strict';

    /* ── Constants ───────────────────────────────────────────── */
    var erReportId       = <?= json_encode($reportId) ?>;
    var erEditable       = <?= $editable ? 'true' : 'false' ?>;
    var erOriginalContent = <?= json_encode($content) ?>;
    var erMd             = null;
    var erDisabledRules  = {};   /* rulename → true when disabled */
    var erRenderingRules = {
        'attribute':         true,
        'attribute-picture': true,
        'object':            true,
        'object-attribute':  true,
        'tag':               true,
        'galaxymatrix':      true,
        'suggestion':        true,
    };
    var erRenderTimer    = null;

    /* ── Bootstrap ───────────────────────────────────────────── */
    document.addEventListener('DOMContentLoaded', function () {
        /* Init markdown-it */
        if (window.markdownit) {
            erMd = window.markdownit({ html: false, linkify: true, typographer: true });
        }

        var editor = document.getElementById('er-editor');
        if (editor) {
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
        }

        /* Initial render + sync all rule badges */
        erRenderLivePreview();
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
        if (!editor || !preview) { return; }

        if (erMd) {
            preview.innerHTML = erMd.render(editor.value);
        } else {
            preview.innerHTML =
                '<pre style="white-space:pre-wrap">' +
                editor.value
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;') +
                '</pre>';
        }
    }

    /* ── Parsing rules toggle ────────────────────────────────── */
    window.erToggleRule = function (rulename, e) {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        if (!erMd) { return; }

        if (erDisabledRules[rulename]) {
            erMd.enable([rulename]);
            delete erDisabledRules[rulename];
        } else {
            erMd.disable([rulename]);
            erDisabledRules[rulename] = true;
        }

        erUpdateRuleUI();
        erRenderLivePreview();
    };

    function erUpdateRuleUI() {
        ['image', 'link'].forEach(function (rule) {
            var badge = document.getElementById('er-rule-' + rule);
            if (!badge) { return; }
            var enabled = !erDisabledRules[rule];
            badge.textContent = enabled ? '<?= __('enabled') ?>' : '<?= __('disabled') ?>';
            badge.className   = 'badge ' + (enabled ? 'bg-success' : 'bg-secondary');
        });

        Object.keys(erRenderingRules).forEach(function (rule) {
            var badge = document.getElementById('er-render-' + rule);
            if (!badge) { return; }
            var enabled = erRenderingRules[rule];
            badge.textContent = enabled ? '<?= __('enabled') ?>' : '<?= __('disabled') ?>';
            badge.className   = 'badge ' + (enabled ? 'bg-success' : 'bg-secondary');
        });
    }

    /* ── Rendering rules toggle ──────────────────────────────── */
    window.erToggleRenderingRule = function (rulename, e) {
        if (e) { e.preventDefault(); e.stopPropagation(); }
        if (erRenderingRules[rulename] === undefined) { return; }

        erRenderingRules[rulename] = !erRenderingRules[rulename];
        erUpdateRuleUI();
        erRenderLivePreview();
    };

    /* ── Download ────────────────────────────────────────────── */
    window.erDownloadMarkdown = function (type, e) {
        if (e) { e.preventDefault(); }

        var editor = document.getElementById('er-editor');
        if (!editor) { return; }
        var raw       = editor.value;
        var timestamp = new Date().getTime();
        var filename  = 'event-report-' + timestamp + '.md';

        if (type === 'pdf-print') {
            var rendered = erMd
                ? erMd.render(raw)
                : '<pre>' + raw.replace(/</g, '&lt;') + '</pre>';

            var win = window.open('', '_blank', 'width=900,height=700');
            win.document.write(
                '<!DOCTYPE html><html><head>' +
                '<meta charset="utf-8"><title>Event Report ' + erReportId + '</title>' +
                '<style>body{font-family:sans-serif;padding:2rem;max-width:800px;margin:auto}' +
                'pre{background:#f4f4f4;padding:1rem;border-radius:4px;overflow-x:auto}' +
                'table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.4rem .6rem}' +
                '</style></head><body>' + rendered + '</body></html>'
            );
            win.document.close();
            win.focus();
            setTimeout(function () { win.print(); }, 400);
            return;
        }

        if (type === 'pdf-module') {
            window.location.href = baseurl + '/eventReports/downloadAsPDF/' + erReportId;
            return;
        }

        /* text / text-gfm — Blob download */
        var fileContent = raw;
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
                /* Sync the read-only preview in the General tab */
                var readonlyPreview = document.getElementById('er-preview-readonly');
                if (readonlyPreview && erMd) {
                    readonlyPreview.innerHTML = erMd.render(editor.value);
                }
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
