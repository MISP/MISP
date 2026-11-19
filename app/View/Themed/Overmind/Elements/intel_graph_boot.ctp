<?php
/**
 * IntelGraph (intel-graph.js), its config and the dock, on every page whose
 * navbar carries the analyst graph slot. The graph itself loads on first use,
 * so its scripts and stylesheets are only listed here, at the URLs the asset
 * loader would give them.
 *
 * @var array $intelGraph `active`: the workspace, {Collection, Graph}
 * @var array|null $intelGraphPage The record on screen a graph can hang off,
 *                                 {type, uuid, label}, set by the view
 * @var string|null $intelGraphShown The graph the page draws in full
 * @var bool $withDock False on a page that draws a graph for a user who has
 *                     no slot to open the dock with
 */
$cachedTimestamp = Configure::read('Asset.timestamp') === 'cached';
$asset = function ($path, $ext) use ($cachedTimestamp, $queryVersion) {
    $url = $this->Html->assetUrl($path, [
        'pathPrefix' => Configure::read($ext === 'js' ? 'App.jsBaseUrl' : 'App.cssBaseUrl'),
        'ext' => '.' . $ext,
    ]);
    $version = $cachedTimestamp && file_exists(WWW_ROOT . $url) ? filemtime(WWW_ROOT . $url) : null;
    return ['path' => $url, 'url' => $url . '?v=' . ($version ?: $queryVersion)];
};

$scripts = [
    'pivotick.iife' => 'Pivotick',
    'misp-pivot-nodes' => 'MispPivotNodes',
    'pivot-sidebar-model' => 'MispPivotSidebar',
    'pivot-sidebar-view' => 'MispPivotSidebarView',
    'pivot-explorer' => 'MispPivotExplorer',
    'analyst-graph' => 'MispAnalystGraph',
];
$js = [];
foreach ($scripts as $path => $global) {
    $js[] = ['global' => $global] + $asset($path, 'js');
}
$css = [];
foreach (['pivotick', 'pivot-explorer', 'pivot-sidebar'] as $path) {
    $css[] = $asset($path, 'css');
}

App::uses('AnalystGraphDocumentTool', 'Tools');
$collectionTypes = [
    'campaign' => __('Campaign'),
    'intrusion_set' => __('Intrusion set'),
    'named_threat' => __('Named threat'),
    'research' => __('Research'),
    'other' => __('Other'),
];
$config = [
    'baseurl' => $baseurl,
    'user' => isset($me['id']) ? (int)$me['id'] : null,
    'limits' => AnalystGraphDocumentTool::limits(),
    'active' => $intelGraph['active'] ?? null,
    'page' => $intelGraphPage ?? null,
    'shown' => $intelGraphShown ?? null,
    'distributionLevels' => $this->DistributionLevel->all(),
    'collectionTypes' => array_map(null, array_keys($collectionTypes), array_values($collectionTypes)),
    'assets' => ['js' => $js, 'css' => $css],
    'canSaveGraph' => $this->Acl->canAccess('analystData', 'add') && $this->Acl->canAccess('analystGraphs', 'save'),
    'explorer' => [
        'orgUuid' => $me['Organisation']['uuid'] ?? '',
        'siteAdmin' => !empty($me['Role']['perm_site_admin']),
        'valueCard' => (bool)Configure::read('MISP.value_hover_card'),
        'canEnrich' => $this->Acl->canAccess('values', 'enrichmentRun'),
        'text' => [
            'libMissing' => __('Graph library failed to load.'),
            'loadFailed' => __('Failed to load the graph.'),
        ],
    ],
    'text' => [
        'none' => __('No workspace'),
    ],
];
?>
<script>
    window.IntelGraphConfig = <?= json_encode($config, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;
</script>
<?php if ($withDock ?? true): ?>
    <?= $this->element('intel_graph_dock') ?>
    <?= $this->element('intel_graph_working_text') ?>
    <template id="ig-collect-dialog">
        <div class="modal fade ig-collect" tabindex="-1" aria-hidden="true" aria-labelledby="ig-collect-title">
            <div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
                <div class="modal-content">
                    <?= $this->element('genericElementsBS5/Forms/modal_header', [
                        'accent' => 'primary',
                        'eyebrow' => __('Collections'),
                        'title' => '',
                        'titleId' => 'ig-collect-title',
                        'titleIcon' => 'fas fa-folder-plus',
                        'titleBadge' => '<span data-ig-collect-title></span>',
                        'description' => __('Collections group the records of an investigation.'),
                        'descriptionClass' => 'ig-collect-sub',
                        'close' => true,
                    ]) ?>
                    <div class="modal-body" data-ig-collect-body></div>
                </div>
            </div>
        </div>
    </template>
    <?= $this->element('genericElements/assetLoader', [
        'js' => ['intel-graph', 'intel-graph-thumb', 'intel-graph-thumbs', 'intel-graph-chooser', 'intel-graph-way-out', 'intel-graph-working', 'intel-graph-dock', 'intel-graph-actions'],
        'css' => ['intel-graph-dock', 'intel-graph-thumbs', 'intel-graph-actions', 'intel-graph-working', 'intel-graph-way-out'],
    ]) ?>
<?php else: ?>
    <?= $this->element('genericElements/assetLoader', ['js' => ['intel-graph']]) ?>
<?php endif; ?>
