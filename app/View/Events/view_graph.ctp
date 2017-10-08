<?php
	if ($scope == 'event') {
		$mayModify = (($isAclModify && $event['Event']['user_id'] == $me['id'] && $event['Orgc']['id'] == $me['org_id']) || ($isAclModifyOrg && $event['Orgc']['id'] == $me['org_id']));
		$mayPublish = ($isAclPublish && $event['Orgc']['id'] == $me['org_id']);
	}
	echo $this->Html->css('font-awesome');
	echo $this->Html->css('correlation-graph');
	echo $this->Html->script('d3');
	echo $this->Html->script('correlation-graph');
?>
<div class="view">
<div id="chart" style="width:100%;height:100%"></div>
	<div id="hover-menu-container" class="menu-container">
		<span class="bold hidden" id="hover-header">Hover target</span><br />
		<ul id="hover-menu" class="menu">
		</ul>
	</div>
	<div id="selected-menu-container" class="menu-container">
		<span class="bold hidden" id="selected-header">Selected</span><br />
		<ul id = "selected-menu" class="menu">
		</ul>
	</div>
	<ul id="context-menu" class="menu">
		<li id="expand">Expand</li>
		<li id="context-delete">Delete</li>
	</ul>
</div>
<div id="graph_init" class="hidden" data-id="<?php echo h($id);?>" data-scope="<?php echo h($scope);?>">
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
	if ($scope == 'event') {
		$params['mayModify'] = $mayModify;
		$params['mayPublish'] = $mayPublish;
	}
	if ($scope == 'tag') {
		if (!empty($taxoomy)) {
			$params['taxonomy'] = $taxonomy['Taxonomy']['id'];
		}
	}
	echo $this->element('side_menu', $params);
?>
