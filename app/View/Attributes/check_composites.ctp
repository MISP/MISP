<div class="composites index">
	<h2>Failed Composites</h2>
	<?php if (0 == count($fails)):?>
	<p>No failed composites</p>
	<?php else:?>
	<ul>
	<?php foreach ($fails as $key => $value) echo '<li>' . $key . ' : ' . h($value) . '</li>'; ?>
	</ul>
	<?php endif;?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>