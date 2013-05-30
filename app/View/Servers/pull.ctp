<div class="servers index">
	<h2>Failed pulls</h2>
	<?php
if (0 == count($fails)):?>
	<p>No failed pulls</p>
	<?php
else:?>
	<ul>
	<?php foreach ($fails as $key => $value) echo '<li>' . $key . ' : ' . h($value) . '</li>'; ?>
	</ul>
	<?php
endif;?>
	<h2>Succeeded pulls</h2>
	<?php
if (0 == count($successes)):?>
	<p>No succeeded pulls</p>
	<?php
else:?>
	<ul>
	<?php foreach ($successes as $success) echo '<li>' . $success . '</li>'; ?>
	</ul>
	<?php
endif;?>
</div>
<div class="actions">
	<ul>
		<li><?php echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add')); ?></li>
		<li><?php echo $this->Html->link(__('List Servers'), array('controller' => 'servers', 'action' => 'index'));?></li>

	</ul>
</div>