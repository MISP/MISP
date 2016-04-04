<?php 
	echo $this->Html->css('tree');
?>
<div>
	<div class="tree">
		<span style="white-space:nowrap;">
			<?php 
				echo $this->Pivot->convertPivotToHTML($pivot, $currentEvent);
			?>
		</span>
	</div>
	<div style="clear:both">
	</div>
</div>
