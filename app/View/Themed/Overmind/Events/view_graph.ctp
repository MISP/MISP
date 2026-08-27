<?= $this->element('genericElements/assetLoader', [
    'css' => ['correlation-graph'],
    'js' => [
        'd3', 
        'correlation-graphOvermind',
        'font-awesome-helper'],
]); ?>

<?php if (!$ajax): ?>
<div class="container-fluid mt-4">
    <div class="card shadow-sm">
        <div class="card-body p-3">
<?php endif; ?>

            <!-- ACTION BAR -->
            <div class="d-flex justify-content-between align-items-center mb-3">

                <div class="d-flex gap-2">
                    <!-- Fullscreen -->
                    <button id="fullscreen-btn-correlation"
                            class="btn btn-outline-primary btn-sm d-flex align-items-center gap-2"
                            data-bs-toggle="tooltip"
                            title="<?= __('Toggle fullscreen') ?>">
                        <i class="fas fa-expand"></i>
                        <?= __('Fullscreen') ?>
                    </button>

                    <!-- Physics toggle -->
                    <button class="btn btn-outline-secondary btn-sm d-flex align-items-center gap-2"
                            onclick="togglePhysics();"
                            title="<?= __('Toggle the physics engine on/off.') ?>">
                        <i class="fas fa-atom"></i>
                        <?= __('Physics') ?>
                    </button>

                    <!-- to_ids filter -->
                    <button id="correlation-toids-btn"
                            class="btn btn-outline-secondary btn-sm d-flex align-items-center gap-2"
                            type="button"
                            aria-pressed="false"
                            title="<?= __('Only show attributes that are flagged as to_ids.') ?>">
                        <i class="fas fa-filter"></i>
                        <?= __('Only to_ids') ?>
                    </button>
                </div>

            </div>

            <!-- GRAPH -->
            <div id="correlationgraph_div" class="graph-container">
                <div id="chart" class="graph-chart"></div>
            </div>

            <!-- HOVER MENU -->
            <div id="hover-menu-container" class="card shadow-sm position-absolute d-none">
                <div class="card-body p-2">
                    <div class="fw-semibold small text-muted mb-1" id="hover-header">
                        <?= __('Hover target') ?>
                    </div>
                    <ul id="hover-menu" class="list-unstyled small mb-0"></ul>
                </div>
            </div>

            <!-- SELECTED MENU -->
            <div id="selected-menu-container" class="card shadow-sm position-absolute d-none">
                <div class="card-body p-2">
                    <div class="fw-semibold small text-muted mb-1" id="selected-header">
                        <?= __('Selected') ?>
                    </div>
                    <ul id="selected-menu" class="list-unstyled small mb-0"></ul>
                </div>
            </div>

            <!-- CONTEXT MENU -->
            <ul id="context-menu"
                class="dropdown-menu shadow"
                style="position:absolute;">
                <li>
                    <button class="dropdown-item" id="expand">
                        <i class="fas fa-expand me-2"></i>
                        <?= __('Expand') ?>
                    </button>
                </li>
                <li>
                    <button class="dropdown-item text-danger" id="context-delete">
                        <i class="fas fa-trash me-2"></i>
                        <?= __('Delete') ?>
                    </button>
                </li>
            </ul>

<?php if (!$ajax): ?>
        </div>
    </div>
</div>
<?php endif; ?>

<!-- INIT DATA -->
<div id="graph_init"
     class="d-none"
     data-id="<?= h($id); ?>"
     data-scope="<?= h($scope); ?>"
     data-ajax="<?= $ajax ? 'true' : 'false'; ?>">
</div>

<?php
$scope_list = [
    'event' => 'event',
    'galaxy' => 'galaxies',
    'tag' => 'tags'
];

$params = [
    'menuList' => $scope_list[$scope],
    'menuItem' => 'viewGraph'
];

if ($scope === 'event') {
    $params['mayModify'] = $mayModify;
    $params['mayPublish'] = $mayPublish;
} elseif ($scope === 'tag' && !empty($taxonomy)) {
    $params['taxonomy'] = $taxonomy['Taxonomy']['id'];
}
?>