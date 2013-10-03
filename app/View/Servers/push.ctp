<div class="servers index">
	<h2>Failed pushes</h2>
	<?php
if (0 == count($fails)):?>
	<p>No failed pushes</p>
	<?php
else:?>
	<ul>
	<?php foreach ($fails as $key => $value) echo '<li>' . $key . ' : ' . h($value) . '</li>'; ?>
	</ul>
	<?php
endif;?>
	<h2>Succeeded pushes</h2>
	<?php
if (0 == count($successes)):?>
	<p>No succeeded pushes</p>
	<?php
else:?>
	<ul>
	<?php foreach ($successes as $success) echo '<li>' . $success . '</li>'; ?>
	</ul>
	<?php
endif;?>
</div>
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('List Servers', array('controller' => 'servers', 'action' => 'index'));?></li>
		<li><?php if ($isSiteAdmin) echo $this->Html->link('New Server', array('controller' => 'servers', 'action' => 'add')); ?></li>
	</ul>
</div>