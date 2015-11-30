<div class="eventAddXML index">
	<h2>Add From MISP Export Result</h2>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th>Event info</th>
			<th>Result</th>
			<th>Details</th>

	</tr>
<?php
	App::uses('JSONConverterTool', 'Tools');
	$converter = new JSONConverterTool();
	foreach ($results as &$result): 
		$status = 'Failed';
		$text = $result['result'];
		$colour = 'red';
		if ($result['result'] === true) {
			$colour = 'green';
			$status = 'OK';
			$text = 'Event created.';
		} else if (is_numeric($result['result'])) {
			$text = 'Event with this UUID already exists.';
		} else {
			$temp = json_decode($text, true);
			$text = $converter->jsonPrinter($temp);
		}
?>
		<tr>
			<td class="short"><?php echo h($result['info']); ?>&nbsp;</td>
			<td class="short" style="color:<?php echo $colour; ?>"><?php echo h($status); ?>&nbsp;</td>
			<td class="short">
				<?php 
					echo nl2br(h($text));
					if (0 !== ($result['id'])) echo ' <a href="' . $baseurl . '/events/view/' . h($result['id']) . '">Event ' . h($result['id']) . '</a>'; 
				?>
				&nbsp;
			</td>
		</tr>
<?php
	endforeach; 
?>
	</table>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'eventBlacklists'));
?>