<?php
$existingFeedUrls = array_values($existingFeedUrls ?? []);
?>

<?= $this->Form->create('Feed', [
    'url' => $baseurl . '/feeds/importFeeds',
    'id' => 'feedImportForm',
    'class' => 'feed-import-form',
    'novalidate' => true,
]) ?>

<!-- ── MODAL HEADER ─────────────────────────────────────────── -->
<div class="px-4 pt-3 pb-3 d-flex align-items-center justify-content-between"
     style="background:rgba(24,146,177,.06);
            border-bottom:2px solid var(--primary);">
    <div>
        <div class="text-primary text-uppercase fw-semibold mb-1"
             style="font-size:.58rem; letter-spacing:.12em; opacity:.85;">
            <?= __('Feeds') ?>
        </div>
        <h4 class="mb-0 fw-bold d-flex align-items-center gap-2">
            <i class="fas fa-file-import text-primary" style="font-size:1.25rem;"></i>
            <?= __('Import Feeds') ?>
        </h4>
        <p class="text-muted mb-0" style="font-size:.75rem;">
            <?= __('Paste feed metadata to create the feeds it describes — a feed already known by its URL is skipped.') ?>
        </p>
    </div>
    <i class="fas fa-rss text-primary" style="font-size:2rem; opacity:.45;"></i>
</div>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── JSON ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="d-flex align-items-center gap-2 text-primary fw-bold
                            text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('Feed Metadata') ?>
                    <span class="badge bg-primary"
                          style="font-size:.55rem; opacity:.8; font-weight:700;">
                        <?= __('REQUIRED') ?>
                    </span>
                </div>
                <div class="d-flex align-items-center gap-2">
                    <span id="feedImportStatus" class="badge bg-secondary"
                          style="font-size:.65rem;"><?= __('Waiting for input') ?></span>
                    <button type="button" class="btn btn-outline-secondary btn-sm"
                            id="feedImportFormatBtn"
                            style="font-size:.7rem; padding:.15rem .5rem;">
                        <i class="fas fa-wand-magic-sparkles me-1"></i><?= __('Format') ?>
                    </button>
                </div>
            </div>

            <?= $this->Form->textarea('json', [
                'id' => 'FeedImportJson',
                'class' => 'w-100 rounded-2 p-3',
                'style' => 'background:var(--bs-tertiary-bg, #f8f9fa);'
                    . ' border:1px solid #d8dde3; resize:vertical;'
                    . ' outline:none; font-size:.85rem; min-height:220px;'
                    . ' color:inherit; font-family:monospace;'
                    . ' white-space:pre; overflow-x:auto;',
                'rows' => 12,
                'spellcheck' => 'false',
                'placeholder' => "[\n    {\n        \"Feed\": {\n            \"name\": \"CIRCL OSINT feed\",\n            \"provider\": \"CIRCL\",\n            \"url\": \"https://www.circl.lu/doc/misp/feed-osint\",\n            \"source_format\": \"misp\"\n        }\n    }\n]",
            ]) ?>
            <div id="feedImportError" class="d-none text-danger
                        d-flex align-items-center gap-1 mt-1"
                 style="font-size:.75rem;"></div>

            <div class="d-flex align-items-center gap-1 mt-1 text-muted"
                 style="font-size:.75rem;">
                <i class="fas fa-circle-info" style="font-size:.65rem;"></i>
                <?= __('Takes the output of a feed index export — one feed object or a list of them.') ?>
            </div>
        </div>

        <!-- ── WHAT WILL BE IMPORTED ───────────────────────────── -->
        <div class="w-100 px-2 d-none" id="feedImportPreviewWrap">
            <div class="d-flex align-items-center justify-content-between mb-2">
                <div class="text-primary fw-bold text-uppercase"
                     style="font-size:.65rem; letter-spacing:.1em;">
                    <?= __('What will be imported') ?>
                </div>
                <div class="d-flex align-items-center gap-1"
                     id="feedImportCounts"></div>
            </div>
            <div class="border rounded" id="feedImportPreview"
                 style="border-color:#d8dde3 !important; max-height:260px;
                        overflow-y:auto;"></div>
        </div>

    </div>

    <!-- ── FOOTER ─────────────────────────────────────────────── -->
    <div class="d-flex justify-content-between align-items-center
                mt-4 pt-3 flex-wrap gap-2">
        <div class="text-muted" style="font-size:.75rem;"
             id="feedImportSummary">
            <i class="fas fa-circle-info me-1" style="font-size:.65rem;"></i>
            <?= __('%s feed(s) already on this instance.', count($existingFeedUrls)) ?>
        </div>
        <div class="d-flex gap-2">
            <button type="button" class="btn btn-outline-secondary btn-sm"
                    data-bs-dismiss="modal">
                <i class="fas fa-times me-1"></i><?= __('Discard') ?>
            </button>
            <?= $this->Form->button(
                '<i class="fas fa-file-import me-1"></i> ' . __('Import'),
                [
                    'class' => 'btn btn-primary btn-sm',
                    'escapeTitle' => false,
                    'type' => 'submit',
                ]
            ) ?>
        </div>
    </div>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var EXISTING = <?= json_encode($existingFeedUrls, JSON_HEX_TAG | JSON_HEX_AMP
        | JSON_HEX_APOS | JSON_HEX_QUOT) ?: '[]' ?>;
    var L = {
        waiting: <?= json_encode(__('Waiting for input')) ?>,
        invalid: <?= json_encode(__('Invalid JSON')) ?>,
        objectExpected: <?= json_encode(__('Expected a feed object or a list of them.')) ?>,
        entryShape: <?= json_encode(__('Entry %s carries no "Feed" object.')) ?>,
        entryUrl: <?= json_encode(__('Entry %s has no url — a feed is recognised by its url.')) ?>,
        ready: <?= json_encode(__('%s to import')) ?>,
        nothingNew: <?= json_encode(__('Nothing new')) ?>,
        newBadge: <?= json_encode(__('NEW')) ?>,
        knownBadge: <?= json_encode(__('KNOWN')) ?>,
        newCount: <?= json_encode(__('%s new')) ?>,
        knownCount: <?= json_encode(__('%s already present')) ?>,
        required: <?= json_encode(__('Please paste the feed metadata to import.')) ?>,
        noName: <?= json_encode(__('(unnamed)')) ?>
    };

    function el(id) { return document.getElementById(id); }

    var jsonEl = el('FeedImportJson');
    var statusEl = el('feedImportStatus');
    var errorEl = el('feedImportError');
    var previewEl = el('feedImportPreview');
    var previewWrap = el('feedImportPreviewWrap');
    var countsEl = el('feedImportCounts');
    var formatBtn = el('feedImportFormatBtn');
    var form = el('feedImportForm');
    if (!jsonEl) { return; }

    function setStatus(kind, text) {
        statusEl.className = 'badge bg-' + kind;
        statusEl.style.fontSize = '.65rem';
        statusEl.textContent = text;
    }

    function setError(message) {
        if (!message) {
            errorEl.classList.add('d-none');
            errorEl.textContent = '';
            return;
        }
        errorEl.classList.remove('d-none');
        errorEl.innerHTML = '';
        var icon = document.createElement('i');
        icon.className = 'fas fa-circle-exclamation';
        errorEl.appendChild(icon);
        errorEl.appendChild(document.createTextNode(message));
    }

    /* Feed::importFeeds() wraps a lone object into a list, so accept both */
    function toEntries(parsed) {
        if (Array.isArray(parsed)) { return parsed; }
        return [parsed];
    }

    function badge(text, kind) {
        var span = document.createElement('span');
        span.className = 'badge flex-shrink-0 ' + kind;
        span.style.fontSize = '.6rem';
        span.textContent = text;
        return span;
    }

    function buildRow(entry, isNew) {
        var feed = entry.Feed || {};
        var row = document.createElement('div');
        row.className = 'd-flex align-items-center gap-2 px-2 py-2 border-bottom';
        row.style.borderColor = '#e9ecef';
        if (!isNew) { row.style.opacity = '.6'; }

        row.appendChild(badge(isNew ? L.newBadge : L.knownBadge,
            isNew ? 'text-bg-success' : 'text-bg-secondary'));

        var body = document.createElement('div');
        body.className = 'flex-fill';
        body.style.minWidth = '0';

        var title = document.createElement('div');
        title.className = 'fw-semibold text-truncate';
        title.style.fontSize = '.8rem';
        title.textContent = feed.name || L.noName;
        if (feed.provider) {
            var provider = document.createElement('span');
            provider.className = 'text-muted fw-normal ms-1';
            provider.style.fontSize = '.75rem';
            provider.textContent = '· ' + feed.provider;
            title.appendChild(provider);
        }
        body.appendChild(title);

        var url = document.createElement('div');
        url.className = 'text-muted font-monospace text-truncate';
        url.style.fontSize = '.72rem';
        url.textContent = feed.url || '';
        body.appendChild(url);
        row.appendChild(body);

        if (feed.source_format) {
            row.appendChild(badge(feed.source_format, 'text-bg-light border'));
        }
        return row;
    }

    function refresh() {
        var raw = jsonEl.value.trim();
        previewWrap.classList.add('d-none');
        if (!raw) {
            setStatus('secondary', L.waiting);
            setError(null);
            return;
        }

        var parsed;
        try {
            parsed = JSON.parse(raw);
        } catch (e) {
            setStatus('danger', L.invalid);
            setError(e.message);
            return;
        }
        if (!parsed || typeof parsed !== 'object') {
            setStatus('danger', L.invalid);
            setError(L.objectExpected);
            return;
        }

        var entries = toEntries(parsed);
        var problem = null;
        for (var i = 0; i < entries.length; i++) {
            var entry = entries[i];
            if (!entry || typeof entry !== 'object' || !entry.Feed) {
                problem = L.entryShape.replace('%s', '#' + (i + 1));
                break;
            }
            if (!entry.Feed.url) {
                problem = L.entryUrl.replace('%s', '#' + (i + 1));
                break;
            }
        }
        if (problem) {
            setStatus('warning', L.invalid);
            setError(problem);
            return;
        }

        setError(null);
        previewEl.innerHTML = '';
        var newCount = 0;
        entries.forEach(function (entry) {
            var isNew = EXISTING.indexOf(entry.Feed.url) === -1;
            if (isNew) { newCount++; }
            previewEl.appendChild(buildRow(entry, isNew));
        });
        var knownCount = entries.length - newCount;

        countsEl.innerHTML = '';
        countsEl.appendChild(badge(L.newCount.replace('%s', newCount),
            'text-bg-success'));
        if (knownCount) {
            countsEl.appendChild(badge(L.knownCount.replace('%s', knownCount),
                'text-bg-secondary'));
        }

        setStatus(newCount ? 'success' : 'secondary',
            newCount ? L.ready.replace('%s', newCount) : L.nothingNew);
        previewWrap.classList.remove('d-none');
    }

    jsonEl.addEventListener('input', refresh);

    if (formatBtn) {
        formatBtn.addEventListener('click', function () {
            try {
                jsonEl.value = JSON.stringify(JSON.parse(jsonEl.value), null, 4);
            } catch (e) { /* refresh() reports it */ }
            refresh();
        });
    }

    if (form) {
        form.addEventListener('submit', function (e) {
            if (jsonEl.value.trim()) { return; }
            e.preventDefault();
            e.stopPropagation();
            jsonEl.style.setProperty('border-color', '#dc3545', 'important');
            setStatus('danger', L.invalid);
            setError(L.required);
            jsonEl.focus();
        });
        jsonEl.addEventListener('input', function () {
            if (jsonEl.value.trim()) {
                jsonEl.style.setProperty('border-color', '#d8dde3', 'important');
            }
        });
    }

    refresh();
})();
</script>
