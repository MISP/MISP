<table class="table table-hover table-condensed">
<tr>
		<th>Test</th>
		<th>Value</th>
		<th>Description</th>
</tr>
<?php 
	$health = array(0 => 'Critical, your MISP instance requires immediate attention.', 1 => 'Issues found, it is recommended that you resolve them.', 2 => 'Good, but there are some optional settings that are incorrect / not set.', 3 => 'In perfect health.');
	$colour = '';
	if ($issues['overallHealth'] < 3) $colour = 'background-color:' . $priorityErrorColours[$issues['overallHealth']] . ';';
	if ($issues['overallHealth'] == 0 || $issues['overallHealth'] == 2) $colour .= 'color:white;';
?>
<tr>
	<td style="<?php echo $colour;?>">Overall health</td>
	<td style="<?php echo $colour;?>"><?php echo h($health[$issues['overallHealth']]);?></td>
	<td style="<?php echo $colour;?>">The overall health of your instance depends on the most severe unresolved issues.</td>
</tr>
<?php 
	foreach ($issues['errors'] as $k => $v): 
		$colour = '';
		if ($k < 3 && $v['value'] > 0) $colour = 'background-color:' . $priorityErrorColours[$k] . ';';
		if ($k == 0 || $k == 2) $colour .= 'color:white;';
?>
<tr>
	<td style="<?php echo $colour; ?>"><?php echo h($priorities[$k]) . ' settings incorrectly or not set';?></td>
	<td style="<?php echo $colour; ?>"><?php echo h($v['value']);?></td>
	<td style="<?php echo $colour; ?>"><?php echo h($v['description']);?></td>
</tr>
<?php endforeach; ?>
</table>