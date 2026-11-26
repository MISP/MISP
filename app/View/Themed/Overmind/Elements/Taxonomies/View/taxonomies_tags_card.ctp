<?php
/*
 * An overview of the taxonomy's values, built like the collection's elements
 * card: filtered and paged in the browser. A tagger can create a missing tag or
 * re-enable a disabled one from here; the rest stays in the Tags tab.
 */
$entries = $entries ?? [];
$pageSize = 50;
$rowActions = [];
if (!empty($isAclTagger) && !empty($data['enabled'])) {
    $addTagUrl = $baseurl . '/taxonomies/addTag/taxonomy_id:' . (int)$data['id'];
    $rowActions = [
        'missing' => ['title' => __('Create tag'), 'url' => $addTagUrl . '/name:'],
        'disabled' => ['title' => __('Enable tag'), 'url' => $addTagUrl . '/enable:1/name:'],
    ];
}

$statuses = [
    'enabled' => ['label' => __('Enabled'), 'icon' => 'fas fa-check', 'class' => 'text-bg-success'],
    'disabled' => ['label' => __('Disabled'), 'icon' => 'fas fa-eye-slash', 'class' => 'text-bg-secondary'],
    'missing' => ['label' => __('Not created'), 'icon' => 'fas fa-plus', 'class' => 'border bg-body text-body-secondary'],
];

$rows = [];
$statusCounts = array_fill_keys(array_keys($statuses), 0);
foreach ($entries as $entry) {
    $tag = $entry['existing_tag']['Tag'] ?? null;
    $status = $tag === null ? 'missing' : (empty($tag['hide_tag']) ? 'enabled' : 'disabled');
    $statusCounts[$status]++;
    $name = (string)($entry['tag'] ?? '');
    $rows[] = [
        'tag' => $name,
        'title' => trim((string)($entry['expanded'] ?? '')) ?: $name,
        'desc' => trim((string)($entry['description'] ?? '')),
        'colour' => $tag['colour'] ?? null,
        'status' => $status,
    ];
}
$statusCounts = array_filter($statusCounts);
$total = count($rows);
?>

<div class="card mb-3 shadow-sm" data-taxonomy-tags data-page-size="<?= (int)$pageSize ?>">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary"
                     style="width:36px;height:36px;">
                    <i class="fas fa-tags"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Tags') ?></div>
                    <div class="small text-muted mt-1">
                        <?= h(__n('%s value defined', '%s values defined', $total, $total)) ?>
                    </div>
                </div>
            </div>

            <?php if ($total > 1): ?>
                <div class="input-group input-group-sm" style="max-width:260px;">
                    <span class="input-group-text border-end-0 bg-body">
                        <i class="fas fa-search text-muted small"></i>
                    </span>
                    <input type="search" class="form-control border-start-0 ps-0"
                           data-tt-search autocomplete="off"
                           placeholder="<?= h(__('Filter tags…')) ?>"
                           aria-label="<?= h(__('Filter tags')) ?>">
                </div>
            <?php endif; ?>

            <a href="#tab-tags" class="btn btn-sm btn-outline-primary flex-shrink-0" data-tt-manage
               title="<?= h(__('Create, enable or disable tags')) ?>">
                <i class="fas fa-sliders me-1"></i><?= __('Manage') ?>
            </a>
        </div>

        <?php if (count($statusCounts) > 1): ?>
            <div class="d-flex flex-wrap gap-1 mt-3" role="group" aria-label="<?= h(__('Filter by status')) ?>">
                <button type="button" class="btn btn-sm rounded-pill btn-primary" data-tt-status="">
                    <?= __('All') ?>
                </button>
                <?php foreach ($statusCounts as $status => $count): ?>
                    <button type="button" class="btn btn-sm rounded-pill btn-outline-secondary d-inline-flex align-items-center gap-1"
                            data-tt-status="<?= h($status) ?>">
                        <i class="<?= h($statuses[$status]['icon']) ?>"></i>
                        <?= h($statuses[$status]['label']) ?>
                        <span class="opacity-75"><?= h($count) ?></span>
                    </button>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($total === 0): ?>
        <div class="card-body text-center text-body-secondary small py-4">
            <i class="fas fa-tags me-1 opacity-50"></i><?= __('This taxonomy defines no value.') ?>
        </div>
    <?php else: ?>
        <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;" data-tt-list></ul>
        <div class="text-center text-body-secondary small py-4 d-none" data-tt-empty>
            <i class="fas fa-filter-circle-xmark me-1 opacity-50"></i><?= __('No tag matches this filter.') ?>
        </div>

        <div class="card-footer bg-body d-flex align-items-center justify-content-between gap-2 py-2 px-3 small text-body-secondary d-none"
             data-tt-footer>
            <span data-tt-count></span>
            <button type="button" class="btn btn-sm btn-link text-decoration-none p-0" data-tt-more>
                <i class="fas fa-chevron-down me-1"></i><?= __('Show more') ?>
            </button>
        </div>

        <template data-tt-row-tpl>
            <li class="list-group-item d-flex align-items-center gap-3 py-2 px-3">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border"
                      style="width:2.25rem;height:2.25rem;" data-tt-tile><i class="fas fa-tag"></i></span>
                <div class="min-w-0 flex-grow-1 lh-sm">
                    <div class="fw-semibold text-truncate" data-tt-title></div>
                    <div class="small text-body-secondary text-truncate mt-1" data-tt-meta></div>
                </div>
                <span class="badge rounded-pill fw-normal flex-shrink-0" data-tt-badge></span>
            </li>
        </template>
        <script type="application/json" data-tt-data><?= json_encode([
            'rows' => $rows,
            'statuses' => $statuses,
            'actions' => (object)$rowActions,
            'i18n' => ['shown' => __('%s of %s shown')],
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?></script>
    <?php endif; ?>
</div>

<script>
(function () {
    document.querySelectorAll('[data-taxonomy-tags]:not([data-tt-bound])').forEach(function (card) {
        card.setAttribute('data-tt-bound', '');
        var manage = card.querySelector('[data-tt-manage]');
        manage.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-tags"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });

        var data = card.querySelector('[data-tt-data]');
        if (!data) {
            return;
        }
        var payload = JSON.parse(data.textContent);
        var pageSize = parseInt(card.dataset.pageSize, 10) || 50;
        var list = card.querySelector('[data-tt-list]');
        var template = card.querySelector('[data-tt-row-tpl]');
        var search = card.querySelector('[data-tt-search]');
        var statusButtons = card.querySelectorAll('[data-tt-status]');
        var empty = card.querySelector('[data-tt-empty]');
        var footer = card.querySelector('[data-tt-footer]');
        var count = card.querySelector('[data-tt-count]');
        var more = card.querySelector('[data-tt-more]');
        var state = { query: '', status: '', limit: pageSize };
        var matching = [];

        payload.rows.forEach(function (row) {
            row.haystack = [row.tag, row.title, row.desc].filter(Boolean).join(' ').toLowerCase();
        });

        function inkFor(hex) {
            var m = /^#?([0-9a-f]{6})$/i.exec(hex || '');
            if (!m) {
                return '#fff';
            }
            var n = parseInt(m[1], 16);
            var luminance = (0.299 * (n >> 16) + 0.587 * ((n >> 8) & 255) + 0.114 * (n & 255)) / 255;
            return luminance > 0.6 ? '#000' : '#fff';
        }

        function buildRow(row) {
            var node = template.content.firstElementChild.cloneNode(true);
            var tile = node.querySelector('[data-tt-tile]');
            if (row.colour) {
                tile.style.background = row.colour;
                tile.style.color = inkFor(row.colour);
                tile.style.borderColor = 'transparent';
            } else {
                tile.classList.add('bg-body-tertiary', 'text-body-secondary');
                tile.style.borderStyle = 'dashed';
            }
            var title = node.querySelector('[data-tt-title]');
            title.textContent = row.title;
            title.title = row.title;

            var meta = node.querySelector('[data-tt-meta]');
            var name = document.createElement('span');
            name.className = 'font-monospace';
            name.textContent = row.tag;
            meta.appendChild(name);
            if (row.desc) {
                meta.appendChild(document.createTextNode(' · '));
                var desc = document.createElement('span');
                desc.className = 'fst-italic';
                desc.textContent = row.desc;
                meta.appendChild(desc);
            }
            meta.title = row.tag + (row.desc ? ' — ' + row.desc : '');

            var status = payload.statuses[row.status];
            var action = payload.actions[row.status];
            var badge = node.querySelector('[data-tt-badge]');
            if (action) {
                var button = document.createElement('button');
                button.type = 'button';
                button.className = badge.className;
                button.title = action.title;
                button.setAttribute('aria-label', action.title + ': ' + row.tag);
                button.addEventListener('click', function () {
                    openModal(action.url + encodeURIComponent(row.tag), 'md');
                });
                badge.replaceWith(button);
                badge = button;
            }
            badge.className += ' ' + status.class;
            var icon = document.createElement('i');
            icon.className = status.icon + ' me-1';
            badge.appendChild(icon);
            badge.appendChild(document.createTextNode(status.label));
            return node;
        }

        function renderPage(from) {
            var fragment = document.createDocumentFragment();
            matching.slice(from, state.limit).forEach(function (row) {
                fragment.appendChild(buildRow(row));
            });
            list.appendChild(fragment);
            var shown = Math.min(state.limit, matching.length);
            empty.classList.toggle('d-none', matching.length !== 0);
            list.classList.toggle('d-none', matching.length === 0);
            footer.classList.toggle('d-none', matching.length <= pageSize);
            more.classList.toggle('d-none', shown >= matching.length);
            count.textContent = payload.i18n.shown.replace('%s', shown).replace('%s', matching.length);
        }

        function apply() {
            matching = payload.rows.filter(function (row) {
                return (state.status === '' || row.status === state.status)
                    && (state.query === '' || row.haystack.indexOf(state.query) !== -1);
            });
            state.limit = pageSize;
            list.replaceChildren();
            list.scrollTop = 0;
            renderPage(0);
        }

        var debounce;
        if (search) {
            search.addEventListener('input', function () {
                clearTimeout(debounce);
                debounce = setTimeout(function () {
                    state.query = search.value.trim().toLowerCase();
                    apply();
                }, 120);
            });
        }
        statusButtons.forEach(function (button) {
            button.addEventListener('click', function () {
                state.status = button.dataset.ttStatus;
                statusButtons.forEach(function (other) {
                    var active = other === button;
                    other.classList.toggle('btn-primary', active);
                    other.classList.toggle('btn-outline-secondary', !active);
                });
                apply();
            });
        });
        more.addEventListener('click', function () {
            var from = state.limit;
            state.limit += pageSize;
            renderPage(from);
        });
        apply();
    });
})();
</script>
