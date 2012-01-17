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
		<td><?php echo $org[0]['amount']; ?>&nbsp;</td>
		
	</tr>
<?php endforeach; ?>
	</table>
	<p>

</div>

<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

