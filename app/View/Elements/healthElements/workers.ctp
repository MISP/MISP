<table class="table table-hover table-condensed" style="border:1px solid #dddddd; margin-top:1px; width:100%; padding:10px">
<tr>
		<th>Worker Type</th>
		<th>Worker Id</th>
		<th>Status</th>
</tr>
<?php 
	foreach ($worker_array as $type => $workers):
		if (empty($workers)):
?>
	<tr>
		<td class="short" style="background-color:red; color:white;"><?php echo (h($type));?></td>
		<td class="short" style="background-color:red; color:white;">N/A</td>
		<td style="background-color:red; color:white;">Worker not running!</td>
	</tr>
<?php 
		else:
			foreach ($workers as $worker):
				$style = "";
				$status = '<span style="color:green;">OK</span>';
?>
	<tr>
		<td class="short" <?php echo $style; ?>><?php echo h($type);?></td>
		<td class="short" <?php echo $style; ?>><?php echo h($worker); ?></td>
		<td <?php echo $style; ?>><?php echo $status; ?></td>
	</tr>
<?php 
			endforeach;
		endif;
?>
<?php 
	endforeach;
?>
</table>
<a href="/servers/restartWorkers" class="btn btn-primary">Restart all workers</a> This will start / restart all of the workers and refresh the page. Keep in mind, this process can take a few seconds to complete, so refresh the page again in 5-10 seconds to see the correct results.