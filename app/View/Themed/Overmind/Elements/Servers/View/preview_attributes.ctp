<?php
/**
 *
 * Read-only attributes index for a remote event preview.
 *
 */

$attributes = array_values(array_filter(
    $data['objects'] ?? [],
    function ($previewObject) {
        return ($previewObject['objectType'] ?? '') === 'attribute';
    }
));

$taggingEnabled = (bool)Configure::read('MISP.tagging');
$uid = 'preview-attrs-' . h($data['Event']['id'] ?? '0');

// Distinct categories / types present, for the "More filters" dropdowns.
$catSet = [];
$typeSet = [];
foreach ($attributes as $a) {
    if (!empty($a['category'])) { $catSet[$a['category']] = true; }
    if (!empty($a['type']))     { $typeSet[$a['type']] = true; }
}
ksort($catSet);
ksort($typeSet);
$catOptions  = ['' => __('All')] + array_combine(array_keys($catSet), array_keys($catSet));
$typeOptions = ['' => __('All')] + array_combine(array_keys($typeSet), array_keys($typeSet));


$paging = $this->params['paging']['Server'] ?? [];
$hasMorePages = !empty($paging['pageCount']) && $paging['pageCount'] > 1;
$viewAllUrl = $baseurl . '/servers/previewEvent/'
    . (int)($server['Server']['id'] ?? 0) . '/'
    . h($data['Event']['id'] ?? '') . '/all#tab-attributes';


$fields = [
    [
        'name' => __('Value'),
        'element' => 'custom',
        'card_section' => 'title',
        'display_in' => ['table', 'card'],
        'function' => function ($row) {
            $dist = $this->element('genericElementsBS5/IndexTable/Fields/distribution', [
                'row' => $row,
                'field' => ['data_path' => 'distribution', 'display' => 'short'],
            ]);
            $html = '<div class="d-flex flex-column gap-1">'
                . '<div class="d-flex align-items-baseline gap-2 mb-0 flex-wrap">'
                . $dist
                . '<p class="mb-0">' . h($row['value'] ?? '') . '</p>'
                . '</div>';
            if (!empty($row['comment'])) {
                $html .= '<div class="card card-link-item bg-light"><div class="card-body p-1">'
                    . '<i class="fa fa-comment"></i> <span>' . h($row['comment']) . '</span>'
                    . '</div></div>';
            }
            return $html . '</div>';
        },
    ],
    [
        'name' => __('Category'),
        'data_path' => 'category',
        'element' => 'category',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Type'),
        'data_path' => 'type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'AttributeTag',
        'element' => 'tag_list',
        'requirement' => $taggingEnabled,
        'card_section' => 'tag',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Galaxy'),
        'data_path' => 'Galaxy',
        'element' => 'galaxy',
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('IDS'),
        'element' => 'custom',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function ($row) {
            $toIds = !empty($row['to_ids']);
            $cls   = $toIds ? 'text-warning' : 'text-secondary';
            $title = $toIds ? __('IDS active') : __('IDS inactive');
            return '<i class="fas fa-shield-halved ' . $cls . '" style="font-size:1.2em;" title="' . h($title) . '"></i>';
        },
    ],
    [
        'name' => __('Correlate'),
        'element' => 'custom',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function ($row) {
            $disabled = !empty($row['disable_correlation']);
            $icon     = $disabled ? 'fa-link-slash' : 'fa-link';
            $cls      = $disabled ? 'text-secondary' : 'text-success';
            $title    = $disabled ? __('Correlation disabled') : __('Correlation enabled');
            return '<i class="fas ' . $icon . ' ' . $cls . '" style="font-size:1.2em;" title="' . h($title) . '"></i>';
        },
    ],
    [
        'name' => __('Related Events'),
        'element' => 'relatedEvents',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Feed hits'),
        'element' => 'feedHits',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Last Modified'),
        'data_path' => 'timestamp',
        'element' => 'timestamp',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['card'],
    ],
    [
        'name' => __('Sightings'),
        'element' => 'sightings',
        'sightings' => ['data' => [], 'csv' => []],
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Analyst data'),
        'element' => 'analyst_data_badges',
        'note_path' => 'Note',
        'opinion_path' => 'Opinion',
        'relationship_path' => 'Relationship',
        'relationship_inbound_path' => 'RelationshipInbound',
        'uuid_path' => 'uuid',
        'object_type' => 'Attribute',
        'card_section' => 'meta',
        'display_in' => ['table', 'card'],
    ],
];


$children = [
    [
        'type' => 'search',
        'button' => __('Search'),
        'placeholder' => __('Filter by value, category, type or tag'),
        'mode' => 'legacy',
        'name' => 'searchFor',
    ],
    [
        'type' => 'more_filters',
        'label' => __('More filters'),
        'children' => [
            ['type' => 'dropdown', 'label' => __('Category'), 'name' => 'category', 'options' => $catOptions],
            ['type' => 'dropdown', 'label' => __('Type'),     'name' => 'type',     'options' => $typeOptions],
        ],
    ],
];
?>

<div id="<?= $uid ?>-scaffold">
    <?php
    echo $this->element('genericElementsBS5/IndexTable/scaffold', [
        'scaffold_data' => [
            'containerId' => $uid . '-index',
            'data' => [
                'data' => $attributes,
                'fields' => $fields,
                'skip_pagination' => true,
                'filter_bar' => [
                    'children' => $children,
                ],
            ]
        ],
        'item_url' => '/attributes'
    ]);
    ?>
</div>

<div id="<?= $uid ?>-noresult" class="d-none text-center text-muted py-4">
    <i class="fas fa-search me-1"></i><?= __('No attribute matches your search') ?>
</div>

<?php if ($hasMorePages): ?>
    <div class="text-center pb-3">
        <a href="<?= h($viewAllUrl) ?>" class="small text-decoration-none">
            <i class="fas fa-list me-1"></i>
            <?= __('This event has more attributes — view all') ?>
        </a>
    </div>
<?php endif; ?>

<?php if (!empty($attributes)): ?>
<script>
(function () {
    var uid   = <?= json_encode($uid) ?>;
    var root  = document.getElementById(uid + '-scaffold');
    if (!root) { return; }
    var noResult = document.getElementById(uid + '-noresult');

    // Strip the filter_bar's own navigation listeners by cloning its controls,
    // then wire client-side filtering (all attributes are already loaded).
    function strip(el) {
        if (!el) { return null; }
        var clone = el.cloneNode(true);
        el.parentNode.replaceChild(clone, el);
        return clone;
    }
    var search  = strip(root.querySelector('#filterField'));
    var btn     = strip(root.querySelector('#filterButton'));
    var selects = Array.prototype.map.call(root.querySelectorAll('.topbar-filter'), strip);

    var rows  = root.querySelectorAll('#tableView tbody tr[data-row-id]');
    var cards = root.querySelectorAll('#cardView .ps-2.pe-2');

    function selByName(name) {
        for (var i = 0; i < selects.length; i++) {
            if (selects[i] && selects[i].getAttribute('name') === name) { return selects[i]; }
        }
        return null;
    }
    var catSel  = selByName('category');
    var typeSel = selByName('type');

    function cellText(row, path) {
        var td = row.querySelector('td[data-path="' + path + '"]');
        return td ? td.textContent.trim() : '';
    }

    function apply() {
        var q   = (search ? search.value : '').toLowerCase().trim();
        var cat = catSel ? catSel.value : '';
        var typ = typeSel ? typeSel.value : '';
        var visible = 0;
        rows.forEach(function (row, i) {
            var show = (q === '' || row.textContent.toLowerCase().indexOf(q) !== -1)
                && (cat === '' || cellText(row, 'category') === cat)
                && (typ === '' || cellText(row, 'type') === typ);
            row.classList.toggle('d-none', !show);
            if (cards[i]) { cards[i].classList.toggle('d-none', !show); }
            if (show) { visible++; }
        });
        if (noResult) { noResult.classList.toggle('d-none', visible !== 0); }
    }

    if (btn)    { btn.addEventListener('click', apply); }
    if (search) {
        search.addEventListener('input', apply);
        search.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); apply(); }
        });
    }
    selects.forEach(function (sel) { if (sel) { sel.addEventListener('change', apply); } });
}());
</script>
<?php endif; ?>
