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
	<h2>Proposals pulled</h2>
	<?php
if (0 == count($pulledProposals)):?>
	<p>No proposals pulled</p>
	<?php
else:?>
	<ul>
	<?php foreach ($pulledProposals as $e => $p) echo '<li>Event ' . $e . ' : ' . $p . ' proposal(s).</li>'; ?>
	</ul>
	<?php
endif;?>

</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'sync', 'menuItem' => 'pull'));
?>
