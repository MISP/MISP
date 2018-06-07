<div id="matrix_container" class="fixed-table-container-inner" style="height: 500px; padding-top: 30px;">
	<div class="header-background"></div>
	<div class="fixed-table-container-inner">
	<table class="table table-condensed matrix-table">
	<thead>
	<tr>
	<?php
		foreach($killChainNames as $kc) {
			$name = str_replace("-", " ", $kc);
			//echo '<th>' . ucfirst($name) .'<div class="extra-wrap"></div>'. '</th>';
			echo '<th><div class="extra-wrap">
				<div class="th-inner">'.ucfirst($name).'</div>
			    </div></th>';
		}
	?>
	</tr>
	</thead>
	<tbody style="overflow-y: scroll;">
	<?php
		$added = false;
		$i = 0;
		do {
			$added = false;
			echo '<tr>';
				foreach($attackClusters as $kc => $clusters) {
					if ($i < count($clusters)) {
						$name = join(" ", array_slice(explode(" ", $clusters[$i]['value']), 0, -2)); // remove " - external_id"
						echo '<td 
							class="matrix-interaction" 
							data-tag_name="'.h($clusters[$i]['tag_name']).'"
							title="'.h($clusters[$i]['external_id']).'"
						    >' . h($name) . '</td>';
						$added = true;
					} else {
						echo '<td class="">' . '</td>';
					}
				}
			echo '</tr>';
			$i++;
		} while($added);
	?>
	</tbody>
	</table>
	</div>
</div>

<?php
	echo $this->Html->script('attack_matrix');
	echo $this->Html->css('attack_matrix');
?>
