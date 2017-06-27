<?php
	echo $this->Html->script('d3');
	echo $this->Html->script('cal-heatmap');
	echo $this->Html->css('cal-heatmap');
?>
<div class = "index">
	<h2>Statistics</h2>
	<?php 
		echo $this->element('Users/statisticsMenu');
		$types = array(
				'local' => array('selected' => false, 'text' => 'Local organisations'),
				'external' => array('selected' => false, 'text' => 'Known remote organisations'),
				'all' => array('selected' => false, 'text' => 'All organisations')
		);
		$types[$scope]['selected'] = true;
	?>
	<p>Quick overview over the organisations residing on or known by this instance.</p>
	<div class="tabMenuFixedContainer" style="display:inline-block;">
			<?php 
				foreach ($types as $key => $value):
			?>
				<span class="tabMenuFixed tabMenuFixedCenter tabMenuSides useCursorPointer <?php if ($value['selected']) echo 'tabMenuActive'; ?>" onclick="window.location='/users/statistics/orgs/scope:<?php echo h($key);?>'"><?php echo h($value['text']); ?></span>
			<?php 
				endforeach;
			?>
	</div>
	<table class="table table-striped table-hover table-condensed" style="width:50%;">
	<tr>
			<th>Logo</th>
			<th>Name</th>
			<th>Users</th>
			<th>Events</th>
			<th>Nationality</th>
			<th>Type</th>
			<th>Sector</th>
	</tr>
	<?php
		foreach ($orgs as $data):
	?>
		<tr class="org_row" data-orgid="<?php echo h($data['id']); ?>">
			<td class="short">
				<?php 
					if (isset($data['logo'])):
				?>
						<img src="<?php echo $baseurl; ?>/img/orgs/<?php echo h($data['name']); ?>.png" height="24" width="24" />
				<?php 
					else:
						echo '&nbsp;';
					endif;
					
				?>
			</td>
			<td class="short"><?php echo h($data['name']); ?></td>
			<td class="short"><span class="<?php echo isset($data['userCount']) ? 'blue bold' : 'grey'; ?>"><?php echo isset($data['userCount']) ? h($data['userCount']) : '0';?></span></td>
			<td class="short"><span class="<?php echo isset($data['eventCount']) ? 'blue bold' : 'grey'; ?>"><?php echo isset($data['eventCount']) ? h($data['eventCount']) : '0';?></span></td>
			<td class="shortish"><?php echo isset($data['nationality']) && $data['nationality'] !== 'Not specified' ? h($data['nationality']) : '&nbsp;'; ?></td>
			<td class="shortish"><?php echo isset($data['type']) ? h($data['type']) : '&nbsp;'; ?></td>
			<td class="shortish"><?php echo isset($data['sector']) ? h($data['sector']) : '&nbsp;'; ?></td>
		</tr>
	<?php
		endforeach;
	?>
	</table>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'statistics'));
?>
<script type="text/javascript">
	$('.org_row').click(function() {
		window.location = "<?php echo $baseurl; ?>/organisations/view/" + $(this).data('orgid');
	});
</script>
