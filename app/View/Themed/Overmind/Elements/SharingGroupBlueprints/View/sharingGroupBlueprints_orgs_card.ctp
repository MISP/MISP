<?php
/*
 * The organisations the blueprint's rules select, built like the collection's
 * elements card: filtered and paged in the browser. Logos only exist as base64,
 * so each distinct one is sent once and rows point at it.
 */
$orgs = $matchingOrgs ?? null;
if ($orgs === null) {
    return;
}
$pageSize = 50;

$logos = [];
$logoIndex = [];
$rows = [];
$scopeCounts = ['local' => 0, 'remote' => 0];
foreach ($orgs as $org) {
    $o = $org['Organisation'];
    $logo = $this->OrgImg->getOrgLogoAsBase64($o);
    $logoRef = null;
    if ($logo !== null) {
        if (!isset($logoIndex[$logo])) {
            $logoIndex[$logo] = count($logos);
            $logos[] = $logo;
        }
        $logoRef = $logoIndex[$logo];
    }
    $scope = !empty($o['local']) ? 'local' : 'remote';
    $scopeCounts[$scope]++;
    $rows[] = [
        'id' => (int)$o['id'],
        'name' => (string)$o['name'],
        'meta' => array_values(array_filter([
            (string)($o['type'] ?? ''),
            (string)($o['sector'] ?? ''),
            (string)($o['nationality'] ?? ''),
        ], 'strlen')),
        'uuid' => (string)$o['uuid'],
        'scope' => $scope,
        'logo' => $logoRef,
    ];
}
$scopeCounts = array_filter($scopeCounts);
$scopes = [
    'local' => ['label' => __('Local'), 'icon' => 'fas fa-house', 'class' => 'text-bg-success'],
    'remote' => ['label' => __('Remote'), 'icon' => 'fas fa-globe', 'class' => 'border bg-body text-body-secondary'],
];
$total = count($rows);
?>

<div class="card mb-3 shadow-sm" data-bp-orgs data-page-size="<?= (int)$pageSize ?>">
    <div class="p-3 border-bottom">
        <div class="d-flex align-items-center gap-3 flex-wrap">
            <div class="d-flex align-items-center gap-2 me-auto">
                <div class="rounded-2 d-flex align-items-center justify-content-center bg-primary-subtle text-primary"
                     style="width:36px;height:36px;">
                    <i class="fas fa-building-user"></i>
                </div>
                <div>
                    <div class="fw-bold lh-1"><?= __('Selected organisations') ?></div>
                    <div class="small text-muted mt-1">
                        <?= h(__n('%s organisation the rules select', '%s organisations the rules select', $total, $total)) ?>
                    </div>
                </div>
            </div>
            <?php if ($total > 1): ?>
                <div class="input-group input-group-sm" style="max-width:260px;">
                    <span class="input-group-text border-end-0 bg-body">
                        <i class="fas fa-search text-muted small"></i>
                    </span>
                    <input type="search" class="form-control border-start-0 ps-0"
                           data-bo-search autocomplete="off"
                           placeholder="<?= h(__('Filter organisations…')) ?>"
                           aria-label="<?= h(__('Filter organisations')) ?>">
                </div>
            <?php endif; ?>
            <a href="#tab-organisations" class="btn btn-sm btn-outline-primary flex-shrink-0" data-bp-tab="organisations"
               title="<?= h(__('Open the full organisation index')) ?>">
                <i class="fas fa-list me-1"></i><?= __('Index') ?>
            </a>
        </div>

        <?php if (count($scopeCounts) > 1): ?>
            <div class="d-flex flex-wrap gap-1 mt-3" role="group" aria-label="<?= h(__('Filter by origin')) ?>">
                <button type="button" class="btn btn-sm rounded-pill btn-primary" data-bo-scope=""><?= __('All') ?></button>
                <?php foreach ($scopeCounts as $scope => $count): ?>
                    <button type="button" class="btn btn-sm rounded-pill btn-outline-secondary d-inline-flex align-items-center gap-1"
                            data-bo-scope="<?= h($scope) ?>">
                        <i class="<?= h($scopes[$scope]['icon']) ?>"></i>
                        <?= h($scopes[$scope]['label']) ?>
                        <span class="opacity-75"><?= h($count) ?></span>
                    </button>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>
    </div>

    <?php if ($total === 0): ?>
        <div class="card-body text-center text-body-secondary small py-4">
            <i class="fas fa-user-slash me-1 opacity-50"></i><?= __('The rules select no organisation.') ?>
        </div>
    <?php else: ?>
        <ul class="list-group list-group-flush overflow-auto" style="max-height:30rem;" data-bo-list></ul>
        <div class="text-center text-body-secondary small py-4 d-none" data-bo-empty>
            <i class="fas fa-filter-circle-xmark me-1 opacity-50"></i><?= __('No organisation matches this filter.') ?>
        </div>
        <div class="card-footer bg-body d-flex align-items-center justify-content-between gap-2 py-2 px-3 small text-body-secondary d-none"
             data-bo-footer>
            <span data-bo-count></span>
            <button type="button" class="btn btn-sm btn-link text-decoration-none p-0" data-bo-more>
                <i class="fas fa-chevron-down me-1"></i><?= __('Show more') ?>
            </button>
        </div>

        <template data-bo-row-tpl>
            <li class="list-group-item d-flex align-items-center gap-2 py-2 px-3">
                <span class="d-inline-flex align-items-center justify-content-center flex-shrink-0 rounded-3 border bg-body-tertiary overflow-hidden"
                      style="width:1.75rem;height:1.75rem;" data-bo-tile></span>
                <div class="min-w-0 me-auto lh-sm">
                    <a class="d-block fw-semibold text-truncate text-decoration-none" data-bo-name></a>
                    <div class="small text-body-secondary text-truncate" data-bo-meta></div>
                </div>
                <span class="badge rounded-pill fw-normal flex-shrink-0" data-bo-badge></span>
            </li>
        </template>
        <script type="application/json" data-bo-data><?= json_encode([
            'rows' => $rows,
            'logos' => $logos,
            'scopes' => $scopes,
            'viewUrl' => $baseurl . '/organisations/view/',
            'i18n' => ['shown' => __('%s of %s shown')],
        ], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE) ?></script>
    <?php endif; ?>
</div>

<script>
(function () {
    document.querySelectorAll('[data-bp-tab]:not([data-bp-bound])').forEach(function (link) {
        link.setAttribute('data-bp-bound', '');
        link.addEventListener('click', function (event) {
            var tab = document.querySelector('.nav-link[href="#tab-' + link.dataset.bpTab + '"]');
            if (tab && window.bootstrap) {
                event.preventDefault();
                bootstrap.Tab.getOrCreateInstance(tab).show();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        });
    });
    document.querySelectorAll('[data-bp-orgs]:not([data-bo-bound])').forEach(function (card) {
        card.setAttribute('data-bo-bound', '');
        var data = card.querySelector('[data-bo-data]');
        if (!data) {
            return;
        }
        var payload = JSON.parse(data.textContent);
        var pageSize = parseInt(card.dataset.pageSize, 10) || 50;
        var list = card.querySelector('[data-bo-list]');
        var template = card.querySelector('[data-bo-row-tpl]');
        var search = card.querySelector('[data-bo-search]');
        var scopeButtons = card.querySelectorAll('[data-bo-scope]');
        var empty = card.querySelector('[data-bo-empty]');
        var footer = card.querySelector('[data-bo-footer]');
        var count = card.querySelector('[data-bo-count]');
        var more = card.querySelector('[data-bo-more]');
        var state = { query: '', scope: '', limit: pageSize };
        var matching = [];

        payload.rows.forEach(function (row) {
            row.haystack = [row.name, row.uuid].concat(row.meta).join(' ').toLowerCase();
        });

        function buildRow(row) {
            var node = template.content.firstElementChild.cloneNode(true);
            var tile = node.querySelector('[data-bo-tile]');
            if (row.logo !== null) {
                var img = document.createElement('img');
                img.src = payload.logos[row.logo];
                img.alt = '';
                img.width = 20;
                img.height = 20;
                tile.appendChild(img);
            } else {
                var icon = document.createElement('i');
                icon.className = 'fas fa-building text-body-secondary';
                tile.appendChild(icon);
            }
            var name = node.querySelector('[data-bo-name]');
            name.textContent = row.name;
            name.title = row.name;
            name.href = payload.viewUrl + row.id;
            node.querySelector('[data-bo-meta]').textContent = row.meta.join(' · ');
            var scope = payload.scopes[row.scope];
            var badge = node.querySelector('[data-bo-badge]');
            badge.className += ' ' + scope.class;
            var glyph = document.createElement('i');
            glyph.className = scope.icon + ' me-1';
            badge.appendChild(glyph);
            badge.appendChild(document.createTextNode(scope.label));
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
                return (state.scope === '' || row.scope === state.scope)
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
        scopeButtons.forEach(function (button) {
            button.addEventListener('click', function () {
                state.scope = button.dataset.boScope;
                scopeButtons.forEach(function (other) {
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
