<div class="servers index">
	<h2>Failed pushes</h2>
	<?php if (0==sizeof($fails)):?>
    <p>No failed pushes</p>
	<?php else:?>
	<ul>
	<?php foreach ($fails as $fail) echo '<li>'.$fail.'</li>'; ?>
	</ul>
	<?php endif;?>
	<h2>Succeeded pushes</h2>
	<?php if (0==sizeof($successes)):?>
	<p>No succeeded pushes</p>
	<?php else:?>
	<ul>
	<?php foreach ($successes as $success) echo '<li>'.$success.'</li>'; ?>
	</ul>
    <?php endif;?>
</div>