<div class="users index">
	<h2>Members</h2>
 	<table class="table table-striped table-condensed table-bordered" style="width:300px;">
	<tr>
			<th>Organisation</th>
			<th># of members</th>
			<th>Logo</th>
 	</tr>
	<?php
foreach ($orgs as $org):?>
	<tr>
		<td><?php echo h($org['User']['org']); ?>&nbsp;</td>
		<td><?php echo h($org[0]['num_members']); ?>&nbsp;</td>
		<?php
			$imgRelativePath = 'orgs' . DS . h($org['User']['org']) . '.png';
			$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
		?>
		<td><?php if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($org['User']['org']) . '.png', array('alt' => h($org['User']['org']),'width' => '48','hight' => '48'));?>&nbsp;</td>
	</tr>
	<?php
endforeach; ?>
	</table>

	<h2>Attribute Types Histogram</h2>
	<div id="graph"></div>
	<script type="text/javascript" src="/js/ext-4.0.7-gpl/bootstrap.js"></script>
	<script>
	Ext.require('Ext.chart.*');
	Ext.require('Ext.layout.container.Fit');

	Ext.onReady(function () {
		var store = Ext.create('Ext.data.JsonStore', {
			fields: [<?php echo $graphFields;?>],
			data: [<?php
foreach ($graphData as $row) {
	echo '{' . $row . '},';
}
?>]
		});
		var panel1 = Ext.create('widget.panel', {
			width: 800,
			height: 1150,
			//title: 'Attributes by Organisation',
			renderTo: 'graph',
			layout: 'fit',
			items: {
				xtype: 'chart',
				animate: true,
				shadow: false,
				store: store,
				legend: {
					position: 'right'
				},
				axes: [{
					type: 'Numeric',
					position: 'bottom',
					fields: [<?php echo $graphFields;?>],
					title: false,
					grid: true,
					label: {
						renderer: function(v) {
							return v;
						}
					},
					roundToDecimal: false
				}, {
					type: 'Category',
					position: 'left',
					fields: ['org'],
					title: false
				}],
				series: [{
					type: 'bar',
					axis: 'bottom',
					gutter: 80,
					xField: 'org',
					yField: [<?php echo $graphFields;?>],
					stacked: true,
					tips: {
						trackMouse: true,
						width: 65,
						height: 28,
						renderer: function(storeItem, item) {
							this.setTitle(item.value[1]);
						}
					}
				}]
			}
		});
	});
	</script>

	<!-- table class="table table-striped table-condensed table-bordered" style="width:400px;">
	<tr>
		<th>Org</th>
		<th>Type</th>
		<th>Amount</th>
	</tr>
	<?php
foreach ($typesHistogram as $item):?>
		<tr>
			<td><?php echo h($item['Event']['org']); ?>&nbsp;</td>
			<td><?php echo h($item['Attribute']['type']); ?>&nbsp;</td>
			<td><?php echo h($item['0']['num_types']); ?>&nbsp;</td>

		</tr>
		<?php
endforeach; ?>
	</table -->

</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'members'));
?>
