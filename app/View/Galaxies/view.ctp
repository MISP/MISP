<?php
	echo $this->element('side_menu', array('menuList' => 'galaxies', 'menuItem' => 'view'));
?>
<div class="galaxy view">
	<div class="row-fluid">
		<div class="span8">
			<h2>
				<span class="fa fa-<?php echo h($galaxy['Galaxy']['icon']); ?>"></span>&nbsp;
				<?php echo h($galaxy['Galaxy']['name']); ?> galaxy
			</h2>
			<dl>
				<dt>Galaxy ID</dt>
				<dd><?php echo h($galaxy['Galaxy']['id']); ?></dd>
				<dt>Name</dt>
				<dd><?php echo $galaxy['Galaxy']['name'] ? h($galaxy['Galaxy']['name']) : h($galaxy['Galaxy']['type']); ?></dd>
				<dt>Uuid</dt>
				<dd><?php echo h($galaxy['Galaxy']['uuid']); ?></dd>
				<dt>Description</dt>
				<dd><?php echo h($galaxy['Galaxy']['description']); ?></dd>
				<dt>Version</dt>
				<dd><?php echo h($galaxy['Galaxy']['version']); ?></dd>

			</dl>
		</div>
	</div>
	<div id="clusters_div"></div>
</div>
<script type="text/javascript">
$(document).ready(function () {
	$.get("/galaxy_clusters/index/<?php echo $galaxy['Galaxy']['id']; ?>", function(data) {
		$("#clusters_div").html(data);
	});
});
</script>
