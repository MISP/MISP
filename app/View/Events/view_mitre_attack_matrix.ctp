<div id="matrix_container" class="fixed-table-container-inner" style="padding-top: 30px;">
	<div class="header-background"></div>
	<div class="fixed-table-container-inner">
	<table class="table table-condensed matrix-table">
	<thead>
	<tr>
	<?php
		foreach($killChainNames as $kc) {
			$name = str_replace("-", " ", $kc);
			echo '<th>
				<div class="extra-wrap">
				    <div class="th-inner">'.ucfirst($name).'</div>
				</div>
			    </th>';
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
					$td = '<td ';
					if ($i < count($clusters)) {
						$tagName = $clusters[$i]['tag_name'];
						$name = join(" ", array_slice(explode(" ", $clusters[$i]['value']), 0, -2)); // remove " - external_id"
						$td .= $heatMap ? ' class="heatCell"' : ' class="matrix-interaction"' ;
						$td .= isset($colours[$tagName]) ? ' style="background: ' . $colours[$tagName] . '; color: ' . $this->TextColour->getTextColour($colours[$tagName]) . '"' : '' ;
						$td .= ' data-tag_name="'.h($tagName).'"';
						$td .= ' title="'.h($clusters[$i]['external_id']).'"';
						$td .= '>' . h($name);
						$added = true;
					} else {
						$td .= 'class="">';
					}
					$td .=  '</td>';
					echo $td;
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
