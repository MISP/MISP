<?php
/*
 * Attribute Categories & Types reference, in three tabs that one search box
 * filters at once:
 *   - Categories : cards, each with its description + compatible-type chips
 *   - Types      : reference table (description, default category, IDS flag)
 *   - Matrix     : sticky compatibility grid (type × category)
 * Every type and category name opens its row or card in the other tab.
 */

$this->set('headerTitle', __('Categories & Types'));
$this->set('headerDescription', __(
    'How MISP describes indicators: every attribute has a <b>type</b> '
    . '(what it is) and lives in a <b>category</b> (why it matters).'
));
$this->set('headerActions', [
    [
        'type' => 'navigate',
        'label' => __('Markdown'),
        'icon' => 'file-arrow-down',
        'url' => $baseurl . '/pages/display/doc/md/categories_and_types',
        'title' => __('Get the .md version (for GitBook generation)'),
    ],
]);

/* ── stable, well-separated colour per category (golden-angle hue wheel) ── */
$catList = array_keys($categoryDefinitions);
$catHue = [];
foreach ($catList as $i => $cat) {
    $catHue[$cat] = (int) round(fmod($i * 137.508, 360));
}
$hueOf = function ($cat) use ($catHue) {
    return isset($catHue[$cat]) ? $catHue[$cat] : 210;
};

$slug = function ($s) {
    return trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($s)), '-');
};

$tabs = [
    'categories' => ['icon' => 'folder-tree', 'title' => __('Categories'), 'count' => count($categoryDefinitions)],
    'types' => ['icon' => 'shapes', 'title' => __('Types'), 'count' => count($typeDefinitions)],
    'matrix' => ['icon' => 'table-cells', 'title' => __('Compatibility matrix'), 'count' => null],
];

$emptyState = function ($icon, $text) {
    return '<div class="d-flex d-none flex-column align-items-center text-secondary py-5" data-ct-empty>'
        . '<i class="fa-solid fa-' . $icon . ' fa-2x mb-2 opacity-50"></i>'
        . h($text) . '</div>';
};
?>

<div class="ct-page container-fluid pb-5">

    <div class="d-flex flex-wrap align-items-end gap-2 border-bottom mb-3">
        <ul class="nav nav-tabs border-0 fs-5" role="tablist">
            <?php foreach ($tabs as $id => $tab): ?>
                <li class="nav-item" role="presentation">
                    <button type="button" role="tab"
                            class="nav-view nav-link d-flex align-items-center gap-2 bg-light text-dark<?= $id === 'categories' ? ' active' : '' ?>"
                            data-bs-toggle="tab" data-bs-target="#ct-<?= $id ?>"
                            aria-selected="<?= $id === 'categories' ? 'true' : 'false' ?>">
                        <i class="fa-solid fa-<?= $tab['icon'] ?>"></i>
                        <?= h($tab['title']) ?>
                        <?php if ($tab['count'] !== null): ?>
                            <span data-ct-count="ct-<?= $id ?>">(<?= (int) $tab['count'] ?>)</span>
                        <?php endif; ?>
                    </button>
                </li>
            <?php endforeach; ?>
        </ul>
        <div class="input-group input-group-sm ms-auto mb-2" style="max-width: 18rem;">
            <span class="input-group-text bg-body"><i class="fa-solid fa-magnifying-glass"></i></span>
            <input type="search" id="ctSearch" class="form-control"
                placeholder="<?= h(__('Filter types & categories…')) ?>"
                autocomplete="off" spellcheck="false">
        </div>
    </div>

    <div class="tab-content">

        <div class="tab-pane fade show active" id="ct-categories" role="tabpanel">
            <div class="row g-3">
                <?php foreach ($categoryDefinitions as $cat => $def): ?>
                    <?php
                        $desc = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
                        $types = $def['types'];
                        $search = strtolower($cat . ' ' . strip_tags($def['desc']) . ' '
                            . implode(' ', $types));
                    ?>
                    <div class="col-12 col-md-6 col-xl-4" data-search="<?= h($search) ?>">
                        <!-- --h cascades to the dot, count badge and type chips inside -->
                        <div class="card h-100 shadow-sm overflow-hidden ct-cat-card"
                                style="--h: <?= $hueOf($cat) ?>;" id="cat-<?= h($slug($cat)) ?>">
                            <div class="d-flex align-items-center gap-2 px-3 pt-3 pb-2">
                                <span class="ct-cat-dot"></span>
                                <h3 class="h6 fw-bold mb-0"><?= h($cat) ?></h3>
                                <span class="badge rounded-pill ms-auto ct-cat-count">
                                    <?= count($types) ?> <?= __('types') ?>
                                </span>
                            </div>
                            <p class="text-secondary small px-3 pb-2 mb-0"><?= $desc /* trusted __() html */ ?></p>
                            <div class="d-flex flex-wrap gap-1 px-3 pb-3">
                                <?php foreach ($types as $t): ?>
                                    <a href="#type-<?= h($slug($t)) ?>" class="ct-chip ct-jump"><?= h($t) ?></a>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
            <?= $emptyState('folder-open', __('No category matches your search.')) ?>
        </div>

        <div class="tab-pane fade" id="ct-types" role="tabpanel">
            <div class="border rounded-3 shadow-sm ct-type-wrap">
                <table class="table table-hover align-middle mb-0 ct-type-table">
                    <thead>
                        <tr>
                            <th class="bg-body-tertiary text-uppercase small text-secondary"
                                style="min-width: 12rem;"><?= __('Type') ?></th>
                            <th class="bg-body-tertiary text-uppercase small text-secondary"
                                style="min-width: 11rem;"><?= __('Default category') ?></th>
                            <th class="bg-body-tertiary text-uppercase small text-secondary text-center"
                                style="width: 5rem;"><?= __('IDS') ?></th>
                            <th class="bg-body-tertiary text-uppercase small text-secondary"><?= __('Description') ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($typeDefinitions as $type => $def): ?>
                            <?php
                                $defCat = isset($def['default_category']) ? $def['default_category'] : null;
                                $hasFormdesc = !empty($def['formdesc'])
                                    && $def['formdesc'] !== ($def['desc'] ?? '');
                                $search = strtolower($type . ' ' . strip_tags($def['desc'] ?? '')
                                    . ' ' . strip_tags($defCat ?? ''));
                            ?>
                            <tr id="type-<?= h($slug($type)) ?>" data-search="<?= h($search) ?>">
                                <td>
                                    <span class="font-monospace fw-semibold text-break"><?= h($type) ?></span>
                                </td>
                                <td>
                                    <?php if ($defCat !== null): ?>
                                        <a href="#cat-<?= h($slug($defCat)) ?>" class="ct-chip ct-jump"
                                            style="--h: <?= $hueOf($defCat) ?>;"><?= h($defCat) ?></a>
                                    <?php else: ?>
                                        <span class="text-secondary">—</span>
                                    <?php endif; ?>
                                </td>
                                <td class="text-center">
                                    <?php if (!empty($def['to_ids'])): ?>
                                        <span class="badge text-bg-success"
                                                title="<?= h(__('Flagged for IDS/detection by default')) ?>">
                                            <i class="fa-solid fa-shield-halved"></i> IDS
                                        </span>
                                    <?php else: ?>
                                        <span class="text-secondary">—</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <div><?= $def['desc'] ?? '' /* trusted __() html */ ?></div>
                                    <?php if ($hasFormdesc): ?>
                                        <div class="small text-secondary mt-1">
                                            <i class="fa-solid fa-circle-info me-1 opacity-75"></i>
                                            <?= $def['formdesc'] ?>
                                        </div>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?= $emptyState('shapes', __('No type matches your search.')) ?>
        </div>

        <div class="tab-pane fade" id="ct-matrix" role="tabpanel">
            <p class="text-secondary small mb-2">
                <i class="fa-solid fa-circle-info me-1"></i>
                <?= __('A dot marks a type that is valid inside a category. '
                    . 'Click a type or a category to open it.') ?>
            </p>
            <div class="overflow-auto border rounded-3 shadow-sm ct-matrix-scroll">
                <table class="small mb-0 ct-matrix">
                    <thead>
                        <tr>
                            <th class="ct-corner align-bottom p-1">
                                <span class="text-secondary small fw-semibold"><?= __('Type ╲ Category') ?></span>
                            </th>
                            <?php foreach ($catList as $cat): ?>
                                <th class="align-bottom p-1" style="--h: <?= $hueOf($cat) ?>;">
                                    <a href="#cat-<?= h($slug($cat)) ?>"
                                        class="ct-vhead ct-jump d-block fw-semibold text-nowrap text-decoration-none mx-auto py-1"
                                        title="<?= h($cat) ?>"><?= h($cat) ?></a>
                                </th>
                            <?php endforeach; ?>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($typeDefinitions as $type => $def): ?>
                            <tr data-search="<?= h(strtolower($type)) ?>">
                                <th class="ct-row-head text-start px-2 py-1">
                                    <a href="#type-<?= h($slug($type)) ?>"
                                        class="ct-jump font-monospace fw-semibold text-nowrap link-body-emphasis link-underline-opacity-0 link-underline-opacity-100-hover"><?= h($type) ?></a>
                                </th>
                                <?php foreach ($catList as $cat): ?>
                                    <td class="p-2">
                                        <?php if (in_array($type, $categoryDefinitions[$cat]['types'], true)): ?>
                                            <span class="ct-dot" style="--h: <?= $hueOf($cat) ?>;"
                                                title="<?= h($cat) ?> · <?= h($type) ?>"></span>
                                        <?php endif; ?>
                                    </td>
                                <?php endforeach; ?>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?= $emptyState('shapes', __('No type matches your search.')) ?>
        </div>

    </div>
</div>

<script>
(function () {
    var page = document.querySelector('.ct-page');
    var search = document.getElementById('ctSearch');
    if (!page || !search) return;

    function applyFilter() {
        var q = search.value.trim().toLowerCase();
        page.querySelectorAll('.tab-pane').forEach(function (pane) {
            var shown = 0;
            pane.querySelectorAll('[data-search]').forEach(function (el) {
                var match = !q || el.dataset.search.indexOf(q) !== -1;
                el.classList.toggle('d-none', !match);
                if (match) shown++;
            });
            pane.querySelector('[data-ct-empty]').classList.toggle('d-none', shown !== 0);
            var count = page.querySelector('[data-ct-count="' + pane.id + '"]');
            if (count) count.textContent = '(' + shown + ')';
        });
    }

    function jump(target) {
        var item = target.closest('[data-search]');
        if (item && item.classList.contains('d-none')) {
            search.value = '';
            applyFilter();
        }
        var pane = target.closest('.tab-pane');
        var tab = page.querySelector('[data-bs-target="#' + pane.id + '"]');
        bootstrap.Tab.getOrCreateInstance(tab).show();
        target.scrollIntoView({ block: 'center', behavior: 'smooth' });
        // restart the animation when the same target is picked twice in a row
        target.classList.remove('ct-flash');
        void target.offsetWidth;
        target.classList.add('ct-flash');
    }

    search.addEventListener('input', applyFilter);
    page.addEventListener('click', function (e) {
        var link = e.target.closest('a.ct-jump');
        var target = link && document.getElementById(link.getAttribute('href').slice(1));
        if (!target) return;
        e.preventDefault();
        jump(target);
    });
})();
</script>
