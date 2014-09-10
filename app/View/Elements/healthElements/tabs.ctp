<div class="tabMenuFixedContainer">
	<span class="tabMenuFixed tabMenuFixedLeft tabMenuSides">
	<a href = "/servers/serverSettings/" id="create-button" title="Modify filters" class="discrete">Overview</a>
	</span>
<?php 
	$i = 0;
	foreach ($tabs as $k => $tab):
		$extra = ''; 
		if ($i == (count($tabs) -1)) $extra = "tabMenuFixedRight"; 
		$label = ucfirst($k) . ' settings';
		$severity = '';
		if ($tab['severity'] == 0) $severity = 'style="color:red;"';
?>
	<span class="tabMenuFixed tabMenuFixedLeft <?php echo h($extra); ?> tabMenuSides">
		<a href = "/servers/serverSettings/<?php echo h($k); ?>" id="create-button" title="Modify filters" class="discrete">
			<?php 
				echo h($label); 
				if ($tab['errors'] > 0) echo '<span ' . $severity . '> (' . $tab['errors'] . ')</span>';
			?>
		</a>
	</span>
<?php 
		$i++;
	endforeach; 
?>
</div>