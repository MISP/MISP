<?php
/*
 * Attribute Categories & Types reference.
 *
 * Rebuilt from the legacy three-table doc page into a searchable, tabbed view.
 * One live-search box filters every tab at once:
 *   - Categories : cards, each with its description + compatible-type pills
 *   - Types      : reference table (description, default category, IDS flag)
 *   - Matrix     : sticky compatibility grid (type × category)
 *
 */

$this->set('headerTitle', __('Categories & Types'));
$this->set('headerDescription', __(
    'How MISP describes indicators: every attribute has a <b>type</b> '
    . '(what it is) and lives in a <b>category</b> (why it matters). '
    . 'Use the search to jump straight to a type or category.'
));

/* ── stable, well-separated colour per category (golden-angle hue wheel) ── */
$catList = array_keys($categoryDefinitions);
$catHue = [];
foreach ($catList as $i => $cat) {
    $catHue[$cat] = (int) round(fmod($i * 137.508, 360));
}
$hueOf = function ($cat) use ($catHue) {
    return isset($catHue[$cat]) ? $catHue[$cat] : 210;
};

/* ── anchor/slug + searchable-string helpers ─────────────────────────────── */
$slug = function ($s) {
    return trim(preg_replace('/[^a-z0-9]+/', '-', strtolower($s)), '-');
};

$idsCount = 0;
foreach ($typeDefinitions as $def) {
    if (!empty($def['to_ids'])) {
        $idsCount++;
    }
}

$this->set('headerStats', [
    [
        'label' => __('Categories'), 'value' => count($categoryDefinitions),
        'color' => 'category', 'icon' => 'folder-tree',
        'subtitle' => __('Contextual buckets'), 'subtitleIcon' => 'layer-group',
    ],
    [
        'label' => __('Types'), 'value' => count($typeDefinitions),
        'color' => 'type', 'icon' => 'shapes',
        'subtitle' => __('Distinct attribute formats'), 'subtitleIcon' => 'fingerprint',
    ],
    [
        'label' => __('IDS-enabled'), 'value' => $idsCount,
        'color' => 'warning', 'icon' => 'shield-halved',
        'subtitle' => __('Actionable for detection by default'),
        'subtitleIcon' => 'bolt',
    ],
    [
        'label' => __('Avg. types / category'),
        'value' => count($categoryDefinitions)
            ? round(array_sum(array_map(function ($c) {
                return count($c['types']);
            }, $categoryDefinitions)) / count($categoryDefinitions))
            : 0,
        'color' => 'info', 'icon' => 'diagram-project',
        'subtitle' => __('Types overlap across categories'),
        'subtitleIcon' => 'code-branch',
    ],
]);
?>

<div class="ct-page container-fluid pb-5">

    <!-- ── sticky toolbar: search + tabs ──────────────────────────────── -->
    <div class="ct-toolbar bg-body border-bottom py-3 mb-4">
        <div class="d-flex flex-wrap align-items-center justify-content-between gap-3">
            <ul class="nav nav-pills gap-1 mb-0" id="ctTabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active fw-semibold d-inline-flex align-items-center gap-2 text-nowrap text-bg-category"
                            data-ct-tab="categories" data-active-bg="text-bg-category" type="button">
                        <i class="fa-solid fa-folder-tree"></i>
                        <?= __('Categories') ?>
                        <span class="badge rounded-pill text-bg-dark"><?= count($categoryDefinitions) ?></span>
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link fw-semibold d-inline-flex align-items-center gap-2 text-nowrap bg-light"
                            data-ct-tab="types" data-active-bg="text-bg-type" type="button">
                        <i class="fa-solid fa-shapes"></i>
                        <?= __('Types') ?>
                        <span class="badge rounded-pill text-bg-dark"><?= count($typeDefinitions) ?></span>
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link fw-semibold d-inline-flex align-items-center gap-2 text-nowrap bg-light"
                            data-ct-tab="matrix" data-active-bg="text-bg-primary" type="button">
                        <i class="fa-solid fa-table-cells"></i>
                        <?= __('Compatibility matrix') ?>
                    </button>
                </li>
            </ul>

            <div class="d-flex align-items-center gap-2">
                <span id="ctCounter" class="text-secondary small d-none d-md-inline"></span>
                <div class="input-group" style="max-width: 22rem;">
                    <span class="input-group-text bg-body"><i class="fa-solid fa-magnifying-glass"></i></span>
                    <input type="search" id="ctSearch" class="form-control"
                        placeholder="<?= h(__('Filter types & categories…')) ?>"
                        autocomplete="off" spellcheck="false">
                </div>
            </div>
        </div>
    </div>

    <!-- ══ TAB: CATEGORIES ═══════════════════════════════════════════════ -->
    <div class="ct-panel" data-ct-panel="categories">
        <div class="row g-3">
            <?php foreach ($categoryDefinitions as $cat => $def): ?>
                <?php
                    $hue = $hueOf($cat);
                    $desc = isset($def['formdesc']) ? $def['formdesc'] : $def['desc'];
                    $types = $def['types'];
                    $search = strtolower($cat . ' ' . strip_tags($def['desc']) . ' '
                        . implode(' ', $types));
                ?>
                <div class="col-12 col-md-6 col-xl-4 ct-item" data-search="<?= h($search) ?>">
                    <!-- --h cascades to the dot, count badge and type chips inside -->
                    <div class="card h-100 shadow-sm overflow-hidden ct-cat-card"
                            style="--h: <?= $hue ?>;" id="cat-<?= h($slug($cat)) ?>">
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
                                <a href="#type-<?= h($slug($t)) ?>" class="ct-chip ct-type-jump"
                                    data-type="<?= h($t) ?>"><?= h($t) ?></a>
                            <?php endforeach; ?>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        </div>
        <div class="text-center text-secondary py-5" data-ct-empty="categories">
            <span class="d-flex flex-column align-items-center">
                <i class="fa-solid fa-folder-open fa-2x mb-2 d-block opacity-50"></i>
                <?= __('No category matches your search.') ?>
            </span>
        </div>
    </div>

    <!-- ══ TAB: TYPES ════════════════════════════════════════════════════ -->
    <div class="ct-panel d-none" data-ct-panel="types">
        <div class="overflow-auto border rounded-3 shadow-sm ct-type-scroll">
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
                            <tr class="ct-item" data-search="<?= h($search) ?>"
                                    id="type-<?= h($slug($type)) ?>">
                                <td>
                                    <span class="font-monospace fw-semibold text-break"><?= h($type) ?></span>
                                </td>
                                <td>
                                    <?php if ($defCat !== null): ?>
                                        <a href="#cat-<?= h($slug($defCat)) ?>" class="ct-chip ct-cat-jump"
                                            style="--h: <?= $hueOf($defCat) ?>;"
                                            data-cat="<?= h($defCat) ?>"><?= h($defCat) ?></a>
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
        <div class="text-center text-secondary py-5" data-ct-empty="types">
            <span class="d-flex flex-column align-items-center">
                <i class="fa-solid fa-shapes fa-2x mb-2 d-block opacity-50"></i>
                <?= __('No type matches your search..') ?>
            </span>
        </div>
    </div>

    <!-- ══ TAB: MATRIX ═══════════════════════════════════════════════════ -->
    <div class="ct-panel d-none" data-ct-panel="matrix">
        <p class="text-secondary small mb-2">
            <i class="fa-solid fa-circle-info me-1"></i>
            <?= __('A dot marks a type that is valid inside a category. '
                . 'Click a column header to open that category.') ?>
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
                                <div class="ct-vhead fw-semibold text-nowrap mx-auto py-1 ct-cat-jump"
                                    data-cat="<?= h($cat) ?>" title="<?= h($cat) ?>"><?= h($cat) ?></div>
                            </th>
                        <?php endforeach; ?>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($typeDefinitions as $type => $def): ?>
                        <tr class="ct-item" data-search="<?= h(strtolower($type)) ?>">
                            <th class="ct-row-head font-monospace fw-semibold text-nowrap text-start px-2 py-1 ct-type-jump"
                                    data-type="<?= h($type) ?>"><?= h($type) ?></th>
                            <?php foreach ($catList as $cat): ?>
                                <td style="padding: 0.60rem;">
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
        <div class="text-center text-secondary py-5" data-ct-empty="matrix">
            <span class="d-flex flex-column align-items-center">
                <i class="fa-solid fa-shapes fa-2x mb-2 d-block opacity-50"></i>
                <?= __('No type matches your search..') ?>
            </span>
        </div>
    </div>

    <!-- ── footer: markdown export ─────────────────────────────────────── -->
    <div class="text-center mt-4">
        <a href="<?= $baseurl ?>/pages/display/doc/md/categories_and_types"
            class="btn btn-sm btn-outline-secondary">
            <i class="fa-brands fa-markdown me-1"></i>
            <?= __('Get the .md version (for GitBook generation)') ?>
        </a>
    </div>

</div>

<script>
(function () {
    var panels = {};
    document.querySelectorAll('.ct-panel').forEach(function (p) {
        panels[p.dataset.ctPanel] = p;
    });
    var tabButtons = document.querySelectorAll('#ctTabs .nav-link');
    var searchInput = document.getElementById('ctSearch');
    var counter = document.getElementById('ctCounter');
    var current = 'categories';

    function activate(tab) {
        current = tab;
        tabButtons.forEach(function (b) {
            var on = b.dataset.ctTab === tab;
            b.classList.toggle('active', on);
            // bg-light by default; the tab's own accent colour when active
            if (on) {
                b.classList.remove('bg-light');
                b.classList.add(b.dataset.activeBg);
            } else {
                b.classList.remove(b.dataset.activeBg);
                b.classList.add('bg-light');
            }
        });
        Object.keys(panels).forEach(function (k) {
            panels[k].classList.toggle('d-none', k !== tab);
        });
        applyFilter();
    }

    tabButtons.forEach(function (b) {
        b.addEventListener('click', function () { activate(b.dataset.ctTab); });
    });

    function applyFilter() {
        var q = searchInput.value.trim().toLowerCase();
        var panel = panels[current];
        if (!panel) return;
        var items = panel.querySelectorAll('.ct-item');
        var shown = 0;
        items.forEach(function (el) {
            var match = !q || (el.dataset.search || '').indexOf(q) !== -1;
            el.classList.toggle('d-none', !match);
            if (match) shown++;
        });
        var empty = panel.querySelector('[data-ct-empty]');
        if (empty) empty.classList.toggle('d-none', shown !== 0);

        var noun = current === 'categories' ? 'categories' : 'types';
        counter.textContent = q
            ? (shown + ' / ' + items.length + ' ' + noun)
            : (items.length + ' ' + noun);
    }

    searchInput.addEventListener('input', applyFilter);

    // Type pill (Categories tab) → jump to Types tab, filter + highlight the row
    function jumpToType(type) {
        activate('types');
        searchInput.value = type;
        applyFilter();
        var row = document.getElementById('type-' + slugify(type));
        if (row) {
            row.classList.add('ct-flash');
            row.scrollIntoView({ block: 'center', behavior: 'smooth' });
            setTimeout(function () { row.classList.remove('ct-flash'); }, 1700);
        }
    }

    // Category chip (Types/Matrix) → open Categories tab + highlight the card
    function jumpToCat(cat) {
        activate('categories');
        searchInput.value = '';
        applyFilter();
        var card = document.getElementById('cat-' + slugify(cat));
        if (card) {
            card.classList.add('ct-flash');
            card.scrollIntoView({ block: 'center', behavior: 'smooth' });
            setTimeout(function () { card.classList.remove('ct-flash'); }, 1700);
        }
    }

    function slugify(s) {
        return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    }

    document.querySelectorAll('.ct-type-jump').forEach(function (el) {
        el.addEventListener('click', function (e) {
            e.preventDefault();
            jumpToType(el.dataset.type);
        });
    });
    document.querySelectorAll('.ct-cat-jump').forEach(function (el) {
        el.addEventListener('click', function (e) {
            e.preventDefault();
            jumpToCat(el.dataset.cat);
        });
    });

    activate(current);
})();
</script>
