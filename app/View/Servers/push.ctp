<div class="servers index">
	<h2>Failed pushes</h2>
	<?php if (0 == count($fails)):?>
	<p>No failed pushes</p>
	<?php else:?>
	<ul>
	<?php foreach ($fails as $key => $value) echo '<li>' . $key . ' : ' . h($value) . '</li>'; ?>
	</ul>
	<?php endif;?>
	<h2>Succeeded pushes</h2>
	<?php if (0 == count($successes)):?>
	<p>No succeeded pushes</p>
	<?php else:?>
	<ul>
	<?php foreach ($successes as $success) echo '<li>' . $success . '</li>'; ?>
	</ul>
	<?php endif;?>
</div>
<div class="actions">
	<ul>
		<li><?php echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add')); ?></li>
		<li><?php echo $this->Html->link(__('List Servers'), array('controller' => 'servers', 'action' => 'index'));?></li>
		<li>&nbsp;</li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>