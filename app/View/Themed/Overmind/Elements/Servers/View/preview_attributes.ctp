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

// The whole event is on hand, so the tab filters it here: the Filters panel
// lists what the event carries, the rows are those matching.
App::uses('RemoteEventPreviewFilter', 'Tools');
$filters = RemoteEventPreviewFilter::active(
    $this->request->params['named'] ?? [],
    RemoteEventPreviewFilter::ATTRIBUTE_FILTERS
);
$panelChildren = RemoteEventPreviewFilter::children($attributes, [], RemoteEventPreviewFilter::ATTRIBUTE_FILTERS);
$attributes = RemoteEventPreviewFilter::attributes($attributes, $filters);

/*
 * The caller loads the whole remote event — the tab counter and the
 * attribute/object split both need it, because rearrangeEventForView truncates
 * the merged objects array rather than each kind. Rendering every row is a
 * different matter: one row costs ~10 kB of markup, so a 7.8k-attribute event
 * produces an ~84 MB response. Cap what is rendered and say so; $viewAllUrl
 * loads the remainder on demand.
 */
$attributeTotal = count($attributes);
// ~10 kB of markup per row, so 200 keeps the fragment near 2 MB.
$renderCap = 200;
$showAll = !empty($showAllAttributes);
$isCapped = !$showAll && $attributeTotal > $renderCap;
if ($isCapped) {
    $attributes = array_slice($attributes, 0, $renderCap);
}

$taggingEnabled = (bool)Configure::read('MISP.tagging');

// The controller pages the preview under its own model key (Server / Feed) and
// builds the "show every attribute" URL, both carried by $previewContext.
$ctx = $previewContext ?? [];
$paging = $this->params['paging'][$ctx['pagingModel'] ?? 'Server'] ?? [];
/*
 * pageCount is computed from the default page size even when the caller asked
 * for everything (rearrangeEventForView sets page=0, which lifts the limit but
 * leaves pageCount alone), so compare what was actually rendered against the
 * total instead: total_elements is post-truncation, count is not.
 */
$hasMorePages = $isCapped
    || (isset($paging['count'], $paging['total_elements'])
        && $paging['total_elements'] < $paging['count']);
// An explicit null means the caller loads everything up front — there is nothing
// to link to — so this cannot fall back with ??.
$viewAllUrl = array_key_exists('viewAllUrl', $ctx)
    ? $ctx['viewAllUrl']
    : ($baseurl . '/servers/previewEvent/'
        . (int)($server['Server']['id'] ?? 0) . '/'
        . h($data['Event']['id'] ?? '') . '/all#tab-attributes');
// The bar's links start from the tab's own URL, uncapped when it is.
$tabUrl = ($ctx['attributesUrl'] ?? '') . ($showAll ? '/all' : '');
if (!empty($viewAllUrl)) {
    foreach ($filters as $name => $value) {
        $viewAllUrl .= '/' . $name . ':' . rawurlencode($value);
    }
}


// The attribute index's fields (Elements/Attributes/index.ctp), so the table
// and its cards draw a remote attribute as the event's tab draws a local one,
// with nothing to toggle or add.
$fields = [
    [
        'name' => __('Value'),
        'data_path' => '',
        'element' => 'attribute_value',
        'remote' => true,
        'card_section' => 'value',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Category'),
        'data_path' => 'category',
        'element' => 'category',
        'card_section' => 'category',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Type'),
        'data_path' => 'type',
        'element' => 'type',
        'card_section' => 'type',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Tags'),
        'data_path' => 'Tag',
        'element' => 'tag_list',
        'requirement' => $taggingEnabled,
        'card_section' => 'tags',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Galaxy'),
        'data_path' => 'Galaxy',
        'element' => 'galaxy',
        'card_section' => 'galaxies',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('IDS'),
        'data_path' => 'to_ids',
        'element' => 'ids',
        'readonly' => true,
        'class' => 'text-center',
        'display_in' => ['table'],
    ],
    [
        'name' => __('Correlate'),
        'data_path' => 'disable_correlation',
        'element' => 'correlate',
        'readonly' => true,
        'class' => 'text-center',
        'display_in' => ['table'],
    ],
    [
        'name' => __('Related Events'),
        'element' => 'relatedEvents',
        'card_section' => 'related',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Feed hits'),
        'element' => 'feedHits',
        'card_section' => 'feeds',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('Sightings'),
        'element' => 'sightings',
        'sightings' => ['data' => [], 'csv' => []],
        'readonly' => true,
        'card_section' => 'sightings',
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
        'card_section' => 'analyst',
        'display_in' => ['table', 'card'],
    ],
];


$children = array_merge([
    [
        'type' => 'search',
        'button' => __('Search'),
        'placeholder' => __('Filter by attribute value, UUID or comment'),
        'mode' => 'legacy',
        'name' => 'searchFor',
    ],
], $panelChildren);

echo $this->element('genericElementsBS5/IndexTable/scaffold', [
    'scaffold_data' => [
        'data' => [
            'data' => $attributes,
            'fields' => $fields,
            'cards_per_row' => ['' => 1, 'lg' => 2, 'xxl' => 3, 'xxxxl' => 4],
            'card_element' => 'Attributes/index_card_tile',
            'card_params' => ['readonly' => true],
            'skip_pagination' => true,
            'empty_message' => empty($filters) ? __('No attributes in this event.') : __('No attribute matches these filters.'),
            'filter_bar' => [
                'base_url' => $tabUrl,
                // Paging belongs to the preview request, not to this bar; the
                // "view all" link below is the way out of the first page.
                'skip_pagination' => true,
                'children' => $children,
            ],
        ]
    ],
    'item_url' => '/attributes'
]);
?>

<?php if ($hasMorePages && !empty($viewAllUrl)): ?>
    <div class="text-center pb-3">
        <?php if ($isCapped): ?>
            <div class="text-muted small mb-1">
                <?= __('Showing the first %1$s of %2$s attributes.', number_format($renderCap), number_format($attributeTotal)) ?>
            </div>
        <?php endif; ?>
        <a href="<?= h($viewAllUrl) ?>" class="small text-decoration-none preview-attrs-view-all">
            <i class="fas fa-list me-1"></i>
            <?= __('Load every attribute') ?>
        </a>
    </div>
    <script>
    (function () {
        // Inside a lazily-loaded tab, swap the fragment in place instead of
        // navigating the whole page away from the preview.
        document.querySelectorAll('.preview-attrs-view-all').forEach(function (link) {
            var container = link.closest('.ajax-tab-content');
            if (!container || typeof reloadAjaxTabIndex !== 'function') { return; }
            link.addEventListener('click', function (e) {
                e.preventDefault();
                reloadAjaxTabIndex(container, link.getAttribute('href'));
            });
        });
    }());
    </script>
<?php endif; ?>
