<?php 
	echo $this->Html->css('tree');
?>
<div>
	<h3>Pivot Thread</h3>
	<div>
		<?php 
			//echo $this->Html->link('Reset thread', array('controller' => 'events', 'action' => 'view', $event['Event']['id']));
		?>
	</div>
	<div class="tree">
		<?php 
			echo $this->Pivot->convertPivotToHTML($pivot, $currentEvent);
		?>
	</div>
	<div style="clear:both">
	</div>
</div>
