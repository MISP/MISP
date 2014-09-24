<table class="table table-hover table-condensed">
<tr>
		<th>Worker Type</th>
		<th>Worker Id</th>
		<th>Status</th>
		<th>Current Job</th>
</tr>
<?php 
	foreach ($worker_array as $type => $workers):
		if (empty($workers)):
?>
	<tr>
		<td class="short" style="background-color:red; color:white;"><?php echo (h($type));?></td>
		<td class="short" style="background-color:red; color:white;">N/A</td>
		<td style="background-color:red; color:white;">Worker not running!</td>
		<td class="short" style="background-color:red; color:white;">N/A</td>
	</tr>
<?php 
		else:
			foreach ($workers as $worker):
				$style = "";
				$status = '<span style="color:green;">OK</span>';
				if ($worker['paused'] || $worker['shutdown']) {
					$style = 'style="background-color:red; color:white;"';
					if ($worker['shutdown']) $status = "Worker shut down.";
					else $status = "Worker paused.";
				}
				$job = $worker['currentJob'];
				if ($job === null) $job = "Worker idle";
?>
	<tr>
		<td class="short" <?php echo $style; ?>><?php echo h($type);?></td>
		<td class="short" <?php echo $style; ?>><?php echo h($worker['id']); ?></td>
		<td <?php echo $style; ?>><?php echo $status; ?></td>
		<td class="short" <?php echo $style; ?>><?php echo h($job); ?></td>
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