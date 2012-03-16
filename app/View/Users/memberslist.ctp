<div class="users index">
	<h2>Members</h2>
 	<table cellpadding="0" cellspacing="0" style="width:300px;">
	<tr>
			<th>Organisation</th>
			<th># of members</th>
 	</tr>
	<?php
	foreach ($orgs as $org):
	?>
	<tr>
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
	foreach ($types_histogram as $item):
	?>
		<tr>
			<td><?php echo $item['Event']['org']; ?>&nbsp;</td>
			<td><?php echo $item['Signature']['type']; ?>&nbsp;</td>
			<td><?php echo $item['0']['num_types']; ?>&nbsp;</td>
			
		</tr>
	<?php endforeach; ?>
	
	
	</table>

</div>

<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

