<?= $this->element('genericElements/assetLoader', [
    'css' => ['font-awesome', 'pivotick', 'correlation-graph-pivotick'],
    'js' => [
        'font-awesome-helper',
        'pivotick/pivotick.umd',
        'correlation-graph-pivotick'
    ],
]);
?>
<?php
    if (!$ajax):
?>
    <div class="view">
<?php endif; ?>
    <span id="fullscreen-btn-correlation" class="fullscreen-btn-correlation btn btn-xs btn-primary" data-toggle="tooltip" data-placement="top" data-title="<?php echo __('Toggle fullscreen');?>"><span class="fa fa-desktop"></span></span>
    <div id="correlation-graph-container" style="width:100%;height:100%;position:relative;"></div>
<?php
    if (!$ajax):
?>
    </div>
<?php endif; ?>
<div id="graph_init" class="hidden" data-id="<?php echo h($id);?>" data-scope="<?php echo h($scope);?>" data-ajax="<?php echo $ajax ? 'true' : 'false'; ?>">
</div>
<?php
    $scope_list = array(
        'event' => 'event',
        'galaxy' => 'galaxies',
        'tag' => 'tags'
    );
    $params = array(
        'menuList' => $scope_list[$scope],
        'menuItem' => 'viewGraph'
    );
    if ($scope === 'event') {
        $params['mayModify'] = $mayModify;
        $params['mayPublish'] = $mayPublish;
    } else if ($scope === 'tag') {
        if (!empty($taxonomy)) {
            $params['taxonomy'] = $taxonomy['Taxonomy']['id'];
        }
    }

    if (!$ajax) {
        echo $this->element('/genericElements/SideMenu/side_menu', $params);
    }
