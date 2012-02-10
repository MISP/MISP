<div class="users index">
	<h2><?php __('Members');?></h2>
 	<table cellpadding="0" cellspacing="0" style="width:300px;">
	<tr>
			<th>Organisation</th>
			<th># of members</th>
 	</tr>
	<?php
	$i = 0;
	foreach ($orgs as $org):
		$class = null;
		if ($i++ % 2 == 0) {
			$class = ' class="altrow"';
		}
	?>
	<tr<?php echo $class;?>>
		<td><?php echo $org['User']['org']; ?>&nbsp;</td>
		<td><?php echo $org[0]['num_members']; ?>&nbsp;</td>
		
	</tr>
<?php endforeach; ?>
	</table>
	
	
	<h2>Signature Types Histogram</h2>
	<table cellpadding="0" cellspacing="0" style="width:400px;">
	<tr>
		<th>Org</th>
		<th>Type</th>
		<th>Amount</th>
	</tr>
	<?php 
	// LATER beautify types_histogram
	$i = 0;
	foreach ($types_histogram as $item):
	$class = null;
	if ($i++ % 2 == 0) {
	    $class = ' class="altrow"';
	}
	?>
		<tr<?php echo $class;?>>
			<td><?php echo $item['Event']['org']; ?>&nbsp;</td>
			<td><?php echo $item['Signature']['type']; ?>&nbsp;</td>
			<td><?php echo $item['0']['num_types']; ?>&nbsp;</td>
			
		</tr>
	<?php endforeach; ?>
	
	
	</table>

</div>

<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

