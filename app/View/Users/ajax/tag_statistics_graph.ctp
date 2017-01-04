<?php
	echo $this->Html->script('d3');
?>
<div id="treemapSettings">
	<div class="row">
	<?php 
		foreach ($taxonomies as $k => $taxonomy):
	?> 
		<div class="span3" style="cursor: pointer;">
			<span id="<?php echo $taxonomy . '-colour'?>" class="attributehistogram-legend-box" style="display: block;float: left;margin: 4px 6px 0 0;background-color:white;">&nbsp;</span>
			<span class="treemap-selector bold" data-treemap-selector="<?php echo h($taxonomy); ?>"><?php echo h($taxonomy); ?></span>
		</div>
	<?php 
		if (($k+1) % 12 == 0) {
			echo '</div><div class="row">';
		}
		endforeach;
	?>
	</div>
</div>
<div id="treemapGraph"></div>
<script>
	var root = <?php echo json_encode($treemap); ?>;
	var flatData = <?php echo json_encode($flatData); ?>;
	var taxonomies = <?php echo json_encode($taxonomies); ?>;
	var hiddenTaxonomies = [];
</script>
<?php echo $this->Html->script('treemap'); ?>