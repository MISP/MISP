<?php

$feedId = (int)$feed['Feed']['id'];
$feedName = !empty($feed['Feed']['provider'])
    ? sprintf('%s (%s)', $feed['Feed']['name'], $feed['Feed']['provider'])
    : $feed['Feed']['name'];

$previewBase = $baseurl . '/feeds/previewIndex/' . $feedId;
$eventViewURL = $baseurl . '/feeds/previewEvent/' . $feedId . '/%id%';
// One and the same endpoint for a single row and for the toolbar selection: it
// renders the confirmation modal on GET and fetches on POST.
$massFetchURL = '/feeds/getSelectedEvents/' . $feedId;
$eventFetchURL = $baseurl . $massFetchURL . '/%id%';

// Fetching is only possible on an enabled feed, and only by a site admin.
$canFetch = !empty($feed['Feed']['enabled']) && !empty($isSiteAdmin);

$this->set('headerTitle', h($feed['Feed']['name']));
$this->set('headerDescription', __('Feed event index preview'));
$this->set('headerActions', [
    [
        'type' => 'navigate',
        'label' => __('Back to feeds'),
        'icon' => 'arrow-left',
        'url' => $baseurl . '/feeds/index'
    ]
]);

/*
 * The manifest rows are flat and keyed by uuid; nest them under `Event` and
 * carry the key in as `Event.uuid` so the row actions have an id to build on.
 */
$previewEvents = [];
foreach ($events as $uuid => $manifestEvent) {
    $manifestEvent['uuid'] = $uuid;
    $manifestEvent['distribution'] = $feed['Feed']['distribution'];
    $previewEvents[$uuid] = ['Event' => $manifestEvent];
}

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'Event.uuid',
        'requirement' => $canFetch,
        'card_section' => 'selector',
    ],
    [
        'name' => __('Info'),
        'sort' => 'info',
        'data_path' => 'Event',
        'element' => 'event_info',
        // The manifest carries no published state
        'published_path' => null,
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Distribution'),
        'data_path' => 'Event.distribution',
        'element' => 'distribution',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Creator Org'),
        'data_path' => 'Event.Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Tags'),
        'requirement' => Configure::read('MISP.tagging'),
        'data_path' => 'Event.Tag',
        'element' => 'tag_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'date',
        'data_path' => 'Event.date',
        'element' => 'datetime',
        'mode' => 'created',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Last Modified'),
        'sort' => 'timestamp',
        'data_path' => 'Event.timestamp',
        'element' => 'datetime',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Event.uuid',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => array_values(array_filter([
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $eventViewURL
            ],
            $canFetch ? [
                'type' => 'modal',
                'label' => __('Fetch this event'),
                'icon' => 'circle-arrow-down',
                'url' => $eventFetchURL,
                'size' => 'sm'
            ] : null,
        ]))
    ],
];
?>

<div class="container-fluid">

    <!-- "You are looking at remote data" indicator kept from the legacy preview -->
    <div class="alert alert-warning d-flex align-items-center gap-2 shadow-sm" role="alert">
        <i class="fas fa-satellite-dish fs-4"></i>
        <div>
            <?= __('You are currently viewing the event index of the feed %s', '<strong>' . h($feedName) . '</strong>') ?>
        </div>
    </div>

    <!-- Search (previewIndex is scoped by a positional feed id, not by named args) -->
    <div class="card shadow-sm mb-4">
        <div class="card-body">
            <div class="d-flex flex-wrap gap-2 align-items-center">
                <div class="flex-grow-1" style="max-width: 600px">
                    <div class="input-group">
                        <input
                            class="form-control"
                            id="previewSearchField"
                            type="text"
                            placeholder="<?= __('Enter value to search') ?>"
                            value="<?= h($this->request->params['named']['searchall'] ?? '') ?>">
                        <button id="previewSearchButton" class="btn btn-primary" type="button">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>
            </div>

            <?php if (!empty($this->request->params['named']['searchall'])): ?>
                <div class="mt-2 d-flex align-items-center flex-wrap gap-2">
                    <strong class="me-1"><?= __('Active filters') ?>:</strong>
                    <span class="badge bg-primary">
                        <?= __('Searchall') ?>: <?= h($this->request->params['named']['searchall']) ?>
                    </span>
                    <a href="<?= h($previewBase) ?>" class="btn btn-sm btn-outline-danger ms-auto">
                        <i class="fas fa-times"></i>
                        <?= __('Clear all') ?>
                    </a>
                </div>
            <?php endif; ?>

            <?php if ($canFetch): ?>
                <?php
                /*
                 * The mass-action toolbar is rendered directly rather than through
                 * filter_bar: this index is scoped by a positional feed id, so the
                 * filter bar's URL building (which targets /feeds/index/...) does
                 * not apply here.
                 */
                echo $this->element('genericElementsBS5/IndexTable/multi_select_toolbar', [
                    'filter_bar' => ['fetch' => true, 'fetch_url' => $massFetchURL],
                    'item_url' => '/feeds',
                ]);
                ?>
            <?php endif; ?>
        </div>
    </div>

    <?php
    echo $this->element('genericElementsBS5/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $previewEvents,
                'fields' => $fields,
                'primary_id_path' => 'Event.uuid',
                'row_dblclick_url' => $eventViewURL,
                // Positional feed id plus the named filter, so paging keeps both.
                'paginatorOptions' => [
                    'url' => array_merge([$feedId], $this->request->params['named'])
                ],
            ]
        ],
        'item_url' => '/feeds'
    ]);
    ?>
</div>

<script>
(function () {
    var previewBase = <?= json_encode($previewBase) ?>;
    var field  = document.getElementById('previewSearchField');
    var button = document.getElementById('previewSearchButton');

    function runSearch() {
        var value = field.value.trim();
        window.location.href = value === ''
            ? previewBase
            : previewBase + '/searchall:' + encodeURIComponent(value);
    }

    if (button) { button.addEventListener('click', runSearch); }
    if (field) {
        field.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') { e.preventDefault(); runSearch(); }
        });
    }
}());
</script>
