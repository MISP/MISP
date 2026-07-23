<?php
/**
 *
 * Remote server event index preview
 *
 */

$serverId   = (int)$server['Server']['id'];
$serverName = !empty($server['Server']['name'])
    ? sprintf('"%s" (%s)', $server['Server']['name'], $server['Server']['url'])
    : sprintf('"%s"', $server['Server']['url']);

$previewBase = $baseurl . '/servers/previewIndex/' . $serverId;
$eventViewURL = $baseurl . '/servers/previewEvent/' . $serverId . '/%id%';
$eventPullURL = $baseurl . '/servers/pull/' . $serverId . '/%id%';

$headerTitle = h($server['Server']['name'] ?: $server['Server']['url']);
$headerDescription = __('Remote instance event index preview');
$headerActions = [
    [
        'type' => 'navigate',
        'label' => __('Back to servers'),
        'icon' => 'arrow-left',
        'url' => $baseurl . '/servers/index'
    ]
];
$this->set('headerTitle', $headerTitle);
$this->set('headerDescription', $headerDescription);
$this->set('headerActions', $headerActions);

$fields = [
    [
        'name' => __('ID'),
        'sort' => 'Event.id',
        'data_path' => 'Event.id',
        'element' => 'id',
        'url' => $eventViewURL,
        'card_section' => 'top',
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
        'name' => __('Info'),
        'data_path' => 'Event',
        'element' => 'event_info',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Published'),
        'sort' => 'Event.published',
        'data_path' => 'Event.published',
        'element' => 'published',
        'card_section' => 'top',
        'display_in' => ['card']
    ],
    [
        'name' => __('Creator Org'),
        'sort' => 'Orgc.name',
        'data_path' => 'Event.Orgc',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Owner Org'),
        'sort' => 'Org.name',
        'data_path' => 'Event.Org',
        'element' => 'organisation',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Tags'),
        'requirement' => Configure::read('MISP.tagging'),
        'data_path' => 'Event.EventTag',
        'element' => 'tag_list',
        'card_section' => 'tag',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Galaxy'),
        'data_path' => 'Event.GalaxyCluster',
        'element' => 'galaxy',
        'card_section' => 'galaxy',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Created'),
        'sort' => 'Event.date',
        'data_path' => 'Event.date',
        'element' => 'timestamp',
        'mode' => 'created',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Last Modified'),
        'sort' => 'Event.timestamp',
        'data_path' => 'Event.timestamp',
        'element' => 'timestamp',
        'mode' => 'modified',
        'card_section' => 'meta',
        'display_in' => ['card']
    ],
    [
        'name' => __('Contents'),
        'data_path' => 'Event',
        'element' => 'event_contents',
        'card_section' => 'meta',
        'display_in' => ['table', 'card']
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'Event.id',
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                'type' => 'navigate',
                'label' => __('View'),
                'icon' => 'eye',
                'url' => $eventViewURL
            ],
            [
                'type' => 'divider',
                'url' => '#'
            ],
            [
                'type' => 'postLink',
                'label' => __('Fetch this event'),
                'icon' => 'arrow-circle-down',
                'url' => $eventPullURL,
                'confirm' => __('Are you sure you want to fetch and save this event on your instance?'),
                'requirement' => function ($row) {
                    return !empty($row['Event']['published']);
                }
            ],
            [
                'type' => 'postLink',
                'label' => __('Fetch this event'),
                'icon' => 'arrow-circle-down',
                'class' => 'text-warning',
                'url' => $eventPullURL,
                'confirm' => __('Are you sure you want to fetch and save this event on your instance? Warning: this event is not published on the remote end.'),
                'requirement' => function ($row) {
                    return empty($row['Event']['published']);
                }
            ]
        ]
    ],
];
?>

<div class="container-fluid">

    <!-- "Remote instance" indicator kept from the legacy preview -->
    <div class="alert alert-warning d-flex align-items-center gap-2 shadow-sm" role="alert">
        <i class="fas fa-satellite-dish fs-4"></i>
        <div>
            <?= __('You are currently viewing the event index of the remote instance %s', '<strong>' . h($serverName) . '</strong>') ?>
        </div>
    </div>

    <!-- Search + active filters (previewIndex uses a positional /<serverId> scope) -->
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
                            value="<?= h($passedArgsArray['searchall'] ?? '') ?>">
                        <button id="previewSearchButton" class="btn btn-primary" type="button">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>
            </div>

            <?php if (!empty($passedArgsArray)): ?>
                <div class="mt-2 d-flex align-items-center flex-wrap gap-2">
                    <strong class="me-1"><?= __('Active filters') ?>:</strong>
                    <?php foreach ($passedArgsArray as $key => $value): ?>
                        <span class="badge bg-primary">
                            <?= h(ucfirst($key)) ?>: <?= h($value) ?>
                        </span>
                    <?php endforeach; ?>
                    <a href="<?= h($previewBase) ?>"
                       class="btn btn-sm btn-outline-danger ms-auto">
                        <i class="fas fa-times"></i>
                        <?= __('Clear all') ?>
                    </a>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <?php
    echo $this->element('genericElementsBS5/IndexTable/scaffold', [
        'scaffold_data' => [
            'data' => [
                'data' => $events,
                'fields' => $fields,
                'primary_id_path' => 'Event.id',
                'row_dblclick_url' => $eventViewURL,
            ]
        ],
        'item_url' => '/servers'
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
