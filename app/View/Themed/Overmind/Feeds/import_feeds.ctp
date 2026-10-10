<?php
$existingFeedUrls = array_values($existingFeedUrls ?? []);
?>

<?= $this->Form->create('Feed', [
    'url' => $baseurl . '/feeds/importFeeds',
    'id' => 'feedImportForm',
    'class' => 'feed-import-form',
    'novalidate' => true,
]) ?>

<?= $this->element('genericElementsBS5/Forms/modal_header', [
    'eyebrow' => __('Feeds'),
    'title' => __('Import Feeds'),
    'description' => __('Paste feed metadata to create the feeds it describes — a feed already known by its URL is skipped.'),
    'titleIcon' => 'fas fa-file-import',
    'icon' => 'fas fa-rss',
]) ?>

<div class="container-fluid px-4 py-4">

    <div class="d-flex flex-column gap-4">

        <!-- ── JSON ────────────────────────────────────────────── -->
        <div class="w-100 px-2">
            <?php
            /* The field parses, reports and re-indents the document; what is
             * specific to a feed import is the list under it, which the
             * script below builds from a `misp:json-change`. */
            ?>
            <?= $this->element('genericElementsBS5/Forms/json_field', [
                'field' => 'json',
                'label' => __('Feed Metadata'),
                'required' => true,
                'id' => 'FeedImportJson',
                'rows' => 12,
                'placeholder' => "[\n    {\n        \"Feed\": {\n            \"name\": \"CIRCL OSINT feed\",\n            \"provider\": \"CIRCL\",\n            \"url\": \"https://www.circl.lu/doc/misp/feed-osint\",\n            \"source_format\": \"misp\"\n        }\n    }\n]",
                'hint' => __('Takes the output of a feed index export — one feed object or a list of them.'),
                'preview' => true,
                'previewLabel' => __('What will be imported'),
                'toolbar' => '<span id="feedImportCounts" class="d-flex align-items-center gap-1"></span>',
            ]) ?>
        </div>

    </div>

    <?= $this->element('genericElementsBS5/Forms/modal_footer', [
        'metaId' => 'feedImportSummary',
        'hint' => __('%s feed(s) already on this instance.', count($existingFeedUrls)),
        'submit' => ['label' => __('Import'), 'icon' => 'fas fa-file-import'],
    ]) ?>

</div>

<?= $this->Form->end() ?>

<script>
(function () {
    var EXISTING = <?= json_encode($existingFeedUrls, JSON_HEX_TAG | JSON_HEX_AMP
        | JSON_HEX_APOS | JSON_HEX_QUOT) ?: '[]' ?>;
    var L = {
        entryShape: <?= json_encode(__('Entry %s carries no "Feed" object.')) ?>,
        entryUrl: <?= json_encode(__('Entry %s has no url — a feed is recognised by its url.')) ?>,
        ready: <?= json_encode(__('%s to import')) ?>,
        nothingNew: <?= json_encode(__('Nothing new')) ?>,
        newBadge: <?= json_encode(__('NEW')) ?>,
        knownBadge: <?= json_encode(__('KNOWN')) ?>,
        newCount: <?= json_encode(__('%s new')) ?>,
        knownCount: <?= json_encode(__('%s already present')) ?>,
        noName: <?= json_encode(__('(unnamed)')) ?>
    };

    var jsonEl = document.getElementById('FeedImportJson');
    var countsEl = document.getElementById('feedImportCounts');
    if (!jsonEl) { return; }

    /* Feed::importFeeds() wraps a lone object into a list, so accept both */
    function toEntries(parsed) {
        return Array.isArray(parsed) ? parsed : [parsed];
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

    /* First entry Feed::importFeeds() would not know what to do with */
    function findProblem(entries) {
        for (var i = 0; i < entries.length; i++) {
            var entry = entries[i];
            if (!entry || typeof entry !== 'object' || !entry.Feed) {
                return L.entryShape.replace('%s', '#' + (i + 1));
            }
            if (!entry.Feed.url) {
                return L.entryUrl.replace('%s', '#' + (i + 1));
            }
        }
        return null;
    }

    jsonEl.addEventListener('misp:json-change', function (e) {
        var field = e.detail.field;
        countsEl.innerHTML = '';
        if (!e.detail.valid) {
            field.setPreview(null);
            return;
        }

        var entries = toEntries(e.detail.parsed);
        var problem = findProblem(entries);
        if (problem) {
            field.setProblem(problem);
            field.setPreview(null);
            return;
        }

        var list = document.createElement('div');
        var newCount = 0;
        entries.forEach(function (entry) {
            var isNew = EXISTING.indexOf(entry.Feed.url) === -1;
            if (isNew) { newCount++; }
            list.appendChild(buildRow(entry, isNew));
        });
        var knownCount = entries.length - newCount;

        countsEl.appendChild(badge(L.newCount.replace('%s', newCount),
            'text-bg-success'));
        if (knownCount) {
            countsEl.appendChild(badge(L.knownCount.replace('%s', knownCount),
                'text-bg-secondary'));
        }

        field.setStatus(newCount ? 'success' : 'secondary',
            newCount ? L.ready.replace('%s', newCount) : L.nothingNew);
        field.setPreview(list);
    });

    /* initJsonFields() runs after this script in both paths — the modal open
     * and the page load — so its own first refresh already reaches the
     * listener above. This only covers a container initialised the other way
     * round, and costs one parse. */
    if (jsonEl.jsonField) { jsonEl.jsonField.refresh(); }
})();
</script>
