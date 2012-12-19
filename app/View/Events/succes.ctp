<div class="succes index">
	<h2>Succes</h2><?php
if (0 == count($succes)):?>
	<p>No Successes.</p><?php
else:?>
	<p>Succes, all done.</p><?php
endif;?>
</div>
<div class="actions">
	<ul>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>