<?php

$feedId = (int)$feed['Feed']['id'];
$feedName = !empty($feed['Feed']['provider'])
    ? sprintf('%s (%s)', $feed['Feed']['name'], $feed['Feed']['provider'])
    : $feed['Feed']['name'];

$previewBase = $baseurl . '/feeds/previewIndex/' . $feedId;
$searchAll = (string)($this->request->params['named']['searchall'] ?? '');

$canFetch = !empty($isSiteAdmin);

$this->set('headerTitle', $feed['Feed']['name']);
$this->set('headerDescription', __('Feed attribute preview'));
$this->set('headerActions', [
    [
        'type' => 'navigate',
        'label' => __('Back to feeds'),
        'icon' => 'arrow-left',
        'url' => $baseurl . '/feeds/index'
    ]
]);

$feedDistribution = (int)$feed['Feed']['distribution'];
// Only attached by the controller when the feed distributes to a sharing group.
$sharingGroupName = $feed['SharingGroup']['name'] ?? null;
$sharingGroupUrl = $baseurl . '/sharing_groups/view/'
    . (int)$feed['Feed']['sharing_group_id'];

/*
 * The parsed rows are a flat, unkeyed list; give each one a stable string key so
 * it can carry a checkbox id (a 0 index would read as empty), and build the
 * matching fetch payload — the four fields saveFreetextFeedData() consumes.
 */
$previewAttributes = [];
$rowPayloads = [];
foreach ($attributes as $i => $attribute) {
    $rowKey = 'row' . $i;
    $attribute['rowid'] = $rowKey;
    $attribute['distribution'] = $feedDistribution;
    $previewAttributes[$rowKey] = $attribute;
    $rowPayloads[$rowKey] = [
        'category' => $attribute['category'] ?? '',
        'type' => $attribute['default_type'] ?? '',
        'value' => $attribute['value'] ?? '',
        'to_ids' => !empty($attribute['to_ids']),
    ];
}

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'rowid',
        'remote' => true,
        'requirement' => $canFetch,
        'card_section' => 'selector',
    ],
    [
        'name' => __('Value'),
        'data_path' => '',
        'element' => 'attribute_value',
        'card_section' => 'title',
        'display_in' => ['table', 'card']
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
        'data_path' => 'default_type',
        'element' => 'type',
        'card_section' => 'attribute',
        'display_in' => ['table', 'card'],
    ],
    [
        'name' => __('IDS'),
        'data_path' => 'ids',
        'element' => 'custom',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function ($row) {
            $toIds = !empty($row['to_ids']);
            $cls = $toIds ? 'text-warning' : 'text-secondary';
            $title = $toIds ? __('IDS active') : __('IDS inactive');
            return '<i class="fas fa-shield-halved ' . $cls . '"'
                . ' style="font-size:1.2em;" title="' . h($title) . '"></i>';
        },
    ],
    [
        'name' => __('Correlations'),
        'element' => 'custom',
        'card_section' => 'top',
        'display_in' => ['table', 'card'],
        'function' => function ($row) use ($correlatingEventInfos, $baseurl) {
            if (empty($row['correlations'])) {
                return '<span class="text-muted">-</span>';
            }
            $badges = '';
            foreach ($row['correlations'] as $eventId) {
                $badges .= '<a href="' . $baseurl . '/events/view2/' . (int)$eventId . '"'
                    . ' class="badge rounded-pill bg-light text-primary border text-decoration-none"'
                    . ' title="' . h($correlatingEventInfos[$eventId] ?? '') . '">'
                    . (int)$eventId . '</a>';
            }
            return '<div class="d-flex flex-wrap gap-1">' . $badges . '</div>';
        },
    ],
    [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'rowid',
        'requirement' => $canFetch,
        'card_section' => 'extra',
        'display_in' => ['table', 'card'],
        'actions' => [
            [
                // The values live in the page, not on the server, so the fetch
                // goes through the page's own form rather than a URL.
                'type' => 'js',
                'label' => __('Fetch this value'),
                'icon' => 'circle-arrow-down',
                'onclick' => "freetextFetchRow('%id%');",
            ],
        ],
    ],
];
?>

<div class="container-fluid">

    <div class="alert alert-warning d-flex align-items-center gap-2 shadow-sm" role="alert">
        <i class="fas fa-satellite-dish fs-4"></i>
        <div>
            <?= __(
                'You are currently viewing the attributes parsed from the %1$s feed %2$s',
                '<strong>' . h($feed['Feed']['source_format']) . '</strong>',
                '<strong>' . h($feedName) . '</strong>'
            ) ?>
        </div>
    </div>

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
                            value="<?= h($searchAll) ?>">
                        <button id="previewSearchButton" class="btn btn-primary" type="button">
                            <i class="fas fa-search"></i>
                        </button>
                    </div>
                </div>
            </div>

            <?php if ($searchAll !== ''): ?>
                <div class="mt-2 d-flex align-items-center flex-wrap gap-2">
                    <strong class="me-1"><?= __('Active filters') ?>:</strong>
                    <span class="badge bg-primary">
                        <?= __('Searchall') ?>: <?= h($searchAll) ?>
                    </span>
                    <a href="<?= h($previewBase) ?>" class="btn btn-sm btn-outline-danger ms-auto">
                        <i class="fas fa-times"></i>
                        <?= __('Clear all') ?>
                    </a>
                </div>
            <?php endif; ?>

            <?php if ($canFetch): ?>
                <?php
                echo $this->element('genericElementsBS5/IndexTable/multi_select_toolbar', [
                    'filter_bar' => [
                        'custom_actions' => [
                            [
                                'id' => 'mass-fetch-freetext-button',
                                'label' => __('Fetch selected'),
                                'icon' => 'circle-arrow-down',
                                'onclick' => 'freetextFetchSelected();',
                            ],
                        ],
                    ],
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
                'data' => $previewAttributes,
                'fields' => $fields,
                'primary_id_path' => 'rowid',
                'paginatorOptions' => [
                    'url' => array_merge([$feedId], $this->request->params['named'])
                ],
            ]
        ],
        'item_url' => '/feeds'
    ]);
    ?>

    <?php if ($canFetch): ?>
        <?php
        //Hidden carrier form for the fetch.
        echo '<div class="d-none">';
        echo $this->Form->create('Feed', [
            'id' => 'FreetextFetchForm',
            'url' => [
                'controller' => 'feeds',
                'action' => 'fetchSelectedFromFreetextIndex',
                $feedId
            ]
        ]);
        echo $this->Form->input('data', [
            'label' => false,
            'div' => false,
            'style' => 'display:none;'
        ]);
        echo $this->Form->end();
        echo '</div>';
        ?>
    <?php endif; ?>
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

    // Remote values may contain anything, including markup — keep them out of
    // the parser's way.
    var payloads = <?= json_encode(
        $rowPayloads,
        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT
    ) ?>;
    var messages = {
        title: <?= json_encode(__('Fetch data from feed')) ?>,
        one: <?= json_encode(__('Fetch and save this attribute on your instance?')) ?>,
        many: <?= json_encode(__('Fetch and save %s attributes on your instance?')) ?>,
        confirm: <?= json_encode(__('Fetch')) ?>,
        cancel: <?= json_encode(__('Cancel')) ?>,
        copied: <?= json_encode(__('Value copied to clipboard')) ?>
    };

    document.addEventListener('click', function (e) {
        var copyButton = e.target.closest('.freetext-copy');
        if (!copyButton) { return; }
        e.preventDefault();
        copyValueToClipboard(copyButton.dataset.value, messages.copied);
    });

    function fetchRows(rowKeys) {
        var payload = rowKeys
            .map(function (key) { return payloads[key]; })
            .filter(Boolean);
        if (!payload.length) { return; }

        var body = payload.length === 1
            ? '<p class="mb-0">' + escapeHtml(messages.one) + '</p>'
              + '<p class="font-monospace text-break mb-0 mt-2">'
              + escapeHtml(payload[0].value) + '</p>'
            : '<p class="mb-0">'
              + escapeHtml(messages.many.replace('%s', payload.length)) + '</p>';

        showConfirmModal({
            title: messages.title,
            body: body,
            confirmLabel: messages.confirm,
            cancelLabel: messages.cancel,
            onConfirm: function () {
                document.getElementById('FeedData').value = JSON.stringify(payload);
                document.getElementById('FreetextFetchForm').submit();
            }
        });
    }

    // Called from the mass-action toolbar and from the per-row action.
    window.freetextFetchSelected = function () {
        fetchRows(Array.from(selectedItems.keys()));
    };
    window.freetextFetchRow = function (rowKey) {
        fetchRows([rowKey]);
    };
}());
</script>
