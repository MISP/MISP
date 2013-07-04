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
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('List Servers', array('controller' => 'servers', 'action' => 'index'));?></li>
		<li><?php if ($isAclAdd && $me['org'] == 'ADMIN') echo $this->Html->link('New Server', array('controller' => 'servers', 'action' => 'add')); ?></li>
	</ul>
</div>