<div class="users index">
	<h2>Members</h2>
 	<table class="table table-striped table-condensed table-bordered" style="width:300px;">
	<tr>
			<th>Organisation</th>
			<th># of members</th>
			<th>Logo</th>
 	</tr>
	<?php
foreach ($orgs as $org):?>
	<tr>
		<td><a href="<?php echo $baseurl; ?>/organisations/view/<?php echo h($org['Organisation']['id']);?>"><?php echo h($org['Organisation']['name']); ?></a>&nbsp;</td>
		<td><?php echo h($org[0]['num_members']); ?>&nbsp;</td>
		<?php
			$imgRelativePath = 'orgs' . DS . h($org['Organisation']['name']) . '.png';
			$imgAbsolutePath = APP . WEBROOT_DIR . DS . 'img' . DS . $imgRelativePath;
		?>
		<td><?php if (file_exists($imgAbsolutePath)) echo $this->Html->image('orgs/' . h($org['Organisation']['name']) . '.png', array('alt' => h($org['Organisation']['name']),'width' => '48','hight' => '48'));?>&nbsp;</td>
	</tr>
	<?php
endforeach; ?>
	</table>
	<div id = "histogram"></div>
	<?php //echo $this->element('histogram');?>
<br /><br />
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'members'));
?>
<script type="text/javascript">
// tooltips
$(document).ready(function () {
	updateHistogram('');
});
</script>
