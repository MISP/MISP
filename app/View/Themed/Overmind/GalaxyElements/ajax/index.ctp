<?php
/**
 * Galaxy cluster elements table/json.
 * Rendered as an ajax fragment inside the cluster view "Elements" tab.
 *
 * Available vars: $elements, $clusterId, $context, $canModify,
 * $JSONElements (JSONView only), $passedArgs (json).
 */
$isJson = ($context === 'JSONView');

// Pagination links carry the cluster id + context so the in-tab reload lands on the right slice
$this->Paginator->options(['url' => [$clusterId, 'context' => $context]]);

// Table / JSON view switch, rendered on the right of the filter bar
$viewSwitch = [
    [
        'icon' => 'fas fa-table-list',
        'title' => __('Tabular view'),
        'url' => $baseurl . '/galaxy_elements/index/' . h($clusterId) . '/context:all',
        'active' => !$isJson,
    ],
    [
        'icon' => 'fas fa-code',
        'title' => __('JSON view'),
        'url' => $baseurl . '/galaxy_elements/index/' . h($clusterId) . '/context:JSONView',
        'active' => $isJson,
    ],
];

$fields = [
    [
        'element' => 'checkbox',
        'data_path' => 'GalaxyElement.id',
        'card_section' => 'selector',
    ],
    [
        'name' => __('Key'),
        'sort' => 'key',
        'data_path' => 'GalaxyElement.key',
        'element' => 'custom',
        'function' => function ($row) {
            return '<span class="badge bg-light text-dark border fw-semibold">' . h($row['GalaxyElement']['key'] ?? '') . '</span>';
        },
    ],
    [
        'name' => __('Value'),
        'sort' => 'value',
        'data_path' => 'GalaxyElement.value',
        'element' => 'custom',
        'function' => function ($row) {
            $key = $row['GalaxyElement']['key'] ?? '';
            $value = (string)($row['GalaxyElement']['value'] ?? '');
            if ($key === 'refs' && (strpos($value, 'https://') === 0 || strpos($value, 'http://') === 0)) {
                return '<a href="' . h($value) . '" rel="noreferrer noopener" target="_blank" class="text-decoration-none">'
                    . h($value) . ' <i class="fas fa-arrow-up-right-from-square small opacity-75"></i></a>';
            }
            return h($value);
        },
    ],
];

if ($canModify) {
    $fields[] = [
        'name' => __('Actions'),
        'element' => 'row_actions',
        'data_path' => 'GalaxyElement.id',
        'actions' => [
            [
                'type' => 'modal',
                'label' => __('Delete'),
                'icon' => 'trash',
                'class' => 'text-danger',
                'url' => $baseurl . '/galaxy_elements/deleteSelection/%id%',
                'size' => 'sm',
            ],
        ],
    ];
}
?>



<?php if (empty($elements)): ?>
    <?php
        echo '<div class="text-center text-muted py-5">'
            . '<i class="fas fa-list fa-2x mb-2 opacity-50"></i><br>'
            . __('This cluster has no elements.')
            . '</div>';
    ?>

<?php else: ?>
    <?php if ($isJson): ?>
        <div class="card shadow-sm mb-4">
            <div class="card-body">
                <div class="d-flex flex-wrap gap-2 align-items-center">
                    <div class="ms-auto">
                        <div class="d-flex justify-content-end align-items-center gap-2">
                            <?php if ($canModify): ?>
                                <button type="button" class="btn btn-primary" title="<?= __('Add JSON as cluster\'s elements') ?>"
                                        onclick="openModal('<?= $baseurl ?>/galaxy_elements/flattenJson/<?= h($clusterId) ?>');">
                                    <i class="fas fa-plus me-1"></i><?= __("Add JSON as cluster's elements") ?>
                                </button>
                            <?php endif; ?>
                            <div class="btn-group" role="group">
                                <?php foreach ($viewSwitch as $vs): ?>
                                    <a href="<?= h($vs['url']) ?>"
                                    class="btn btn-outline-primary <?= !empty($vs['active']) ? 'active' : '' ?>"
                                    title="<?= h($vs['title']) ?>">
                                        <i class="<?= h($vs['icon']) ?>"></i>
                                    </a>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="position-relative">
            <button type="button" class="btn btn-sm btn-light position-absolute top-0 end-0 m-2"
                    title="<?= __('Copy to clipboard') ?>"
                    onclick="copyValueToClipboard(document.getElementById('galaxyElementsJson').textContent, '<?= __('JSON copied to clipboard') ?>');">
                <i class="fas fa-copy"></i>
            </button>
            <pre class="bg-light border rounded p-3 mb-0" style="max-height:55vh; overflow:auto;"><code id="galaxyElementsJson"><?= h(json_encode($JSONElements, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)) ?></code></pre>
        </div>

    <?php else: ?>

        <?php
        echo $this->element('genericElementsBS5/IndexTable/scaffold', [
            'scaffold_data' => [
                'data' => [
                    'data' => $elements,
                    'filter_bar' => [
                        'pull' => 'right',
                        'children' => [],
                        'view_switch' => $viewSwitch,
                        'delete' => $canModify ? '/deleteSelection' : null,
                    ],
                    'fields' => $fields,
                    'primary_id_path' => 'GalaxyElement.id',
                ],
            ],
            'item_url' => '/galaxy_elements',
        ]);
        ?>

    <?php endif; ?>
<?php endif; ?>





<script>
(function () {
    var sel = '.ajax-tab-content[data-url*="galaxy_elements/index"]';
    var container = document.querySelector(sel);
    if (!container || container.dataset.elementsWired) return;
    container.dataset.elementsWired = '1';

    // In-tab reload for the view switch and pagination links.
    container.addEventListener('click', function (e) {
        var a = e.target.closest('a[href]');
        if (!a) return;
        var href = a.getAttribute('href');
        if (href && href.indexOf('/galaxy_elements/index') !== -1) {
            e.preventDefault();
            fetch(href, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
                .then(function (r) { return r.text(); })
                .then(function (html) {
                    container.innerHTML = html;
                    container.querySelectorAll('script').forEach(function (o) {
                        var s = document.createElement('script');
                        if (o.src) { s.src = o.src; } else { s.textContent = o.textContent; }
                        document.head.appendChild(s);
                        document.head.removeChild(s);
                    });
                });
        }
    });
})();
</script>
