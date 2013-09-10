<?php 
	echo $this->Html->css('tree');
?>
<div>
	<div class="tree">
		<?php 
			echo $this->Pivot->convertPivotToHTML($pivot, $currentEvent);
		?>
	</div>
	<div style="clear:both">
	</div>
</div>
