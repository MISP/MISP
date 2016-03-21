<?php
	foreach ($results as &$r):
		foreach ($r as $k => &$v): 
?>
			<span class="bold blue"><?php echo h($k);?></span>: <span class="red"><?php echo h($v);?></span><br />
<?php 
		endforeach;
	endforeach;
?>