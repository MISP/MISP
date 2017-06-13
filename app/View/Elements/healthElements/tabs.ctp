<div class="tabMenuFixedContainer">
	<span class="tabMenuFixed tabMenuFixedLeft tabMenuSides">
	<a href="<?php echo $baseurl;?>/servers/serverSettings/" id="create-button" title="Modify filters" class="discrete">Overview</a>
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
		<a href="<?php echo $baseurl."/servers/serverSettings/".h($k); ?>" id="create-button" title="Modify filters" class="discrete">
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
	<span class="tabMenuFixed tabMenuFixedCenter tabMenuSides" style="margin-left:50px;">
	<a href="<?php echo $baseurl;?>/servers/serverSettings/diagnostics" id="create-button" title="Modify filters" class="discrete">
		Diagnostics
		<?php
			if ($diagnostic_errors > 0) echo '<span style="color:red;"> (' . $diagnostic_errors . ')</span>';
		?>
	</a>
	</span>
	<?php if (!empty($worker_array)): ?>
	<span class="tabMenuFixed tabMenuFixedCenter tabMenuSides" style="margin-left:10px;">
		<a href="<?php echo $baseurl;?>/servers/serverSettings/workers" id="create-button" title="Modify filters" class="discrete">
			Workers
			<?php
				if ($workerIssueCount > 0) echo '<span style="color:red;"> (' . $workerIssueCount . ')</span>';
			?>
		</a>
	</span>
	<?php endif; ?>
	<span class="tabMenuFixed tabMenuFixedCenter tabMenuSides" style="margin-left:10px;">
		<a href="<?php echo $baseurl;?>/servers/serverSettings/files" id="download-button" title="Manage files" class="discrete">Manage files</a>
	</span>
	<span class="tabMenuFixed tabMenuFixedCenter tabMenuSides" style="margin-left:10px;">
		<a href="<?php echo $baseurl;?>/servers/serverSettings/download" id="download-button" title="Download report" role="button" tabindex="0" aria-label="Download report" class="useCursorPointer discrete icon-download-alt"></a>
	</span>
</div>
