<?= $this->element('genericElements/assetLoader', [
    'css' => ['font-awesome', 'correlation-graph'],
    'js' => ['d3', 'correlation-graph', 'font-awesome-helper'],
]);
?>
<?php
    if (!$ajax):
?>
    <div class="graph-view">
<?php endif; ?>
    <span id="fullscreen-btn-correlation" class="fullscreen-btn-correlation btn btn-xs btn-primary" data-toggle="tooltip" data-placement="top" data-title="<?php echo __('Toggle fullscreen');?>"><span class="fa fa-desktop"></span></span>
    <div id="chart" style="width:100%;height:100%"></div>
        <div id="hover-menu-container" class="menu-container">
            <span class="bold hidden" id="hover-header"><?php echo __('Hover target');?></span><br>
            <ul id="hover-menu" class="menu">
            </ul>
        </div>
        <div id="selected-menu-container" class="menu-container">
            <span class="bold hidden" id="selected-header"><?php echo __('Selected');?></span><br>
            <ul id="selected-menu" class="menu">
            </ul>
        </div>
        <ul id="context-menu" class="menu">
            <li id="expand"><?php echo __('Expand');?></li>
            <li id="context-delete"><?php echo __('Delete');?></li>
        </ul>
        <button class="correlation-stop-btn btn btn-inverse" onclick="togglePhysics();" title="<?php echo __('Toggle the physics engine on/off.');?>">Toggle physics</button>
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
        if (!empty($taxoomy)) {
            $params['taxonomy'] = $taxonomy['Taxonomy']['id'];
        }
    }

    if (!$ajax) {
        echo $this->element('/genericElements/SideMenu/side_menu', $params);
    }
