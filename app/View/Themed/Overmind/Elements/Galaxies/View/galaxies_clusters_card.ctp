<?php
/*
 * An overview of the galaxy's clusters, built like the collection's elements
 * card: filtered and paged in the browser over the lean list the controller
 * hands over as $clusterPreview. Editing stays in the Clusters tab.
 */
$preview = $clusterPreview ?? [];
$pageSize = 50;
$palette = $this->GalaxyColour->palette($data['name'] ?? '');
$iconClass = !empty($data['icon']) ? $this->FontAwesome->getClass($data['icon']) : 'fas fa-shapes';

$origins = [
    'default' => ['label' => __('Default'), 'icon' => 'fas fa-box'],
    'custom' => ['label' => __('Custom'), 'icon' => 'fas fa-pen-ruler'],
];

$rows = [];
$originCounts = array_fill_keys(array_keys($origins), 0);
foreach ($preview as $cluster) {
    $origin = empty($cluster['GalaxyCluster']['default']) ? 'custom' : 'default';
    $originCounts[$origin]++;
    $desc = trim((string)($cluster[0]['short_description'] ?? ''));
    $rows[] = [
        'id' => (int)$cluster['GalaxyCluster']['id'],
        'value' => (string)$cluster['GalaxyCluster']['value'],
        'desc' => mb_strlen($desc) >= 120 ? $desc . '…' : $desc,
        'origin' => $origin,
    ];
}
$originCounts = array_filter($originCounts);
$total = count($rows);
?>

<div class="card mb-3 shadow-sm" data-galaxy-clusters data-page-size="<?= (int)$pageSize ?>">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center"
                     style="width:36px;height:36px;background:<?= h($palette['tintBg']) ?>;color:<?= h($palette['tintIcon']) ?>;">
                    <i class="fas fa-diagram-project"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Clusters') ?></div>
                    <div class="small text-muted mt-1">
                        <?= h(__n('%s cluster', '%s clusters', $total, $total)) ?>
                    </div>
                </div>
            </div>

            <?php if ($total > 1): ?>
                <div class="input-group input-group-sm" style="max-width:260px;">
                    <span class="input-group-text border-end-0 bg-body">
                        <i class="fas fa-search text-muted small"></i>
                    </span>
                    <input type="search" class="form-control border-start-0 ps-0"
                           data-gc-search autocomplete="off"
                           placeholder="<?= h(__('Filter clusters…')) ?>"
                           aria-label="<?= h(__('Filter clusters')) ?>">
                </div>
            <?php endif; ?>

            <a href="#tab-clusters" class="btn btn-sm btn-outline-primary flex-shrink-0" data-gc-manage
               title="<?= h(__('Open the full cluster index')) ?>">
                <i class="fas fa-list me-1"></i><?= __('Index') ?>
            </a>
        </div>

        <?php if (count($originCounts) > 1): ?>
            <div class="d-flex flex-wrap gap-1 mt-3" role="group" aria-label="<?= h(__('Filter by origin')) ?>">
                <button type="button" class="btn btn-sm rounded-pill btn-primary" data-gc-origin="">
                    <?= __('All') ?>
                </button>
                <?php foreach ($originCounts as $origin => $count): ?>
                    <button type="button" class="btn btn-sm rounded-pill btn-outline-secondary d-inline-flex align-items-center gap-1"
                            data-gc-origin="<?= h($origin) ?>">
                        <i class="<?= h($origins[$origin]['icon']) ?>"></i>
                        <?= h($origins[$origin]['label']) ?>
                        <span class="opacity-75"><?= h($count) ?></span>
                    </button>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($total === 0): ?>
        <div class="card-body text-center text-body-secondary small py-4">
            <i class="fas fa-diagram-project me-1 opacity-50"></i><?= __('This galaxy has no cluster you can see.') ?>
        </div>
    <?php else: ?>
        <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;" data-gc-list></ul>
        <div class="text-center text-body-secondary small py-4 d-none" data-gc-empty>
            <i class="fas fa-filter-circle-xmark me-1 opacity-50"></i><?= __('No cluster matches this filter.') ?>
        </div>

        <div class="card-footer bg-body d-flex align-items-center justify-content-between gap-2 py-2 px-3 small text-body-secondary d-none"
             data-gc-footer>
            <span data-gc-count></span>
            <button type="button" class="btn btn-sm btn-link text-decoration-none p-0" data-gc-more>
                <i class="fas fa-chevron-down me-1"></i><?= __('Show more') ?>
            </button>
        </div>

        <template data-gc-row-tpl>
            <li class="list-group-item list-group-item-action d-flex align-items-center gap-3 py-2 px-3">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3"
                      style="width:2.25rem;height:2.25rem;background:<?= h($palette['tintBg']) ?>;color:<?= h($palette['tintIcon']) ?>;">
                    <i class="<?= h($iconClass) ?>"></i>
                </span>
                <div class="min-w-0 flex-grow-1 lh-sm">
                    <a class="d-block fw-semibold text-truncate text-decoration-none" data-gc-title></a>
                    <div class="small text-body-secondary text-truncate mt-1" data-gc-meta></div>
                </div>
                <span class="badge rounded-pill border bg-body-tertiary text-body-secondary fw-normal flex-shrink-0 d-none" data-gc-custom>
                    <i class="fas fa-pen-ruler me-1 opacity-50"></i><?= __('Custom') ?>
                </span>
            </li>
        </template>
        <script type="application/json" data-gc-data><?= json_encode([
            'rows' => $rows,
            'viewUrl' => $baseurl . '/galaxy_clusters/view/',
            'i18n' => ['shown' => __('%s of %s shown')],
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?></script>
    <?php endif; ?>
</div>

<script>
(function () {
    document.querySelectorAll('[data-galaxy-clusters]:not([data-gc-bound])').forEach(function (card) {
        card.setAttribute('data-gc-bound', '');
        card.querySelector('[data-gc-manage]').addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-clusters"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });

        var data = card.querySelector('[data-gc-data]');
        if (!data) {
            return;
        }
        var payload = JSON.parse(data.textContent);
        var pageSize = parseInt(card.dataset.pageSize, 10) || 50;
        var list = card.querySelector('[data-gc-list]');
        var template = card.querySelector('[data-gc-row-tpl]');
        var search = card.querySelector('[data-gc-search]');
        var originButtons = card.querySelectorAll('[data-gc-origin]');
        var empty = card.querySelector('[data-gc-empty]');
        var footer = card.querySelector('[data-gc-footer]');
        var count = card.querySelector('[data-gc-count]');
        var more = card.querySelector('[data-gc-more]');
        var state = { query: '', origin: '', limit: pageSize };
        var matching = [];

        payload.rows.forEach(function (row) {
            row.haystack = (row.value + ' ' + row.desc).toLowerCase();
        });

        function buildRow(row) {
            var node = template.content.firstElementChild.cloneNode(true);
            var title = node.querySelector('[data-gc-title]');
            title.textContent = row.value;
            title.title = row.value;
            title.href = payload.viewUrl + row.id;
            var meta = node.querySelector('[data-gc-meta]');
            meta.textContent = row.desc;
            meta.title = row.desc;
            if (row.origin === 'custom') {
                node.querySelector('[data-gc-custom]').classList.remove('d-none');
            }
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
                return (state.origin === '' || row.origin === state.origin)
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
        originButtons.forEach(function (button) {
            button.addEventListener('click', function () {
                state.origin = button.dataset.gcOrigin;
                originButtons.forEach(function (other) {
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
