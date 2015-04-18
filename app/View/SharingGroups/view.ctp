<div class="roles view">
<h2><?php  echo __('Sharing Group');?></h2>
<?php 
	$fields = array('id', 'name', 'releasability', 'description', 'active');	
?>
	<dl>
		<?php 
			foreach ($fields as $f):
		?>
		<dt><?php echo ucfirst($f); ?></dt>
		<dd><?php echo h($sg['SharingGroup'][$f]); ?></dd>
		<?php 
			endforeach;
		?>
		<dt>Created by</dt>
		<dd><a href="/organisation/view/<?php echo $sg['Organisation']['id']; ?>"><?php echo h($sg['Organisation']['name']); ?></a></dd>
	</dl>
</div>
<?php 
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'viewSG'));
?>