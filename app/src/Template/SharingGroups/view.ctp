<div class="roles view">
<h2><?php  echo __('Sharing Group');?></h2>
<?php
	$fields = array('id', 'name', 'releasability', 'description', 'active');
?>
	<dl>
		<?php
			foreach ($fields as $f):
		?>
		<dt><?php
			if ($f != 'active') echo ucfirst($f);
			else echo 'Selectable';
		?></dt>
		<dd>
			<?php
				if ($f !== 'active') echo h($sg['SharingGroup'][$f]);
				else echo '<span class="' . ($sg['SharingGroup'][$f] ? 'icon-ok' : 'icon-remove') . '"></span>';
			?>&nbsp;
		</dd>
		<?php
			endforeach;
		?>
		<dt>Created by</dt>
		<dd><a href="/organisations/view/<?php echo $sg['Organisation']['id']; ?>"><?php echo h($sg['Organisation']['name']); ?></a></dd>
		<?php
			if ($sg['SharingGroup']['sync_user_id']):
		?>
			<dt>Synced by</dt>
			<dd><a href="/organisations/view/<?php echo $sg['Organisation']['id']; ?>"><?php echo h($sg['Organisation']['name']); ?></a></dd>
		<?php
			endif;
		?>
	</dl><br />
	<div class="row" style="width:100%;">
	<?php
		if (isset($sg['SharingGroupOrg'])):
	?>
		<div class="span6">
		<b>Organisations</b>
			<table class="table table-striped table-hover table-condensed">
				<tr>
					<th>Name</th>
					<th>Local</th>
					<th>Extend</th>
				</tr>
				<?php
					foreach ($sg['SharingGroupOrg'] as $sgo):
				?>
				<tr>
					<td><a href="/organisations/view/<?php echo h($sgo['Organisation']['id']); ?>"><?php echo h($sgo['Organisation']['name']); ?></a></td>
					<td><span class="<?php echo ($sgo['Organisation']['local'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
					<td><span class="<?php echo ($sgo['extend'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
				</tr>
				<?php
					endforeach;
				?>
			</table>
		</div>
	<?php
		endif;
		if (!$sg['SharingGroup']['roaming']):
	?>
		<div class="span6">
		<b>Instances</b>
			<table class="table table-striped table-hover table-condensed">
				<tr>
					<th>Name</th>
					<th>Url</th>
					<th>All orgs</th>
				</tr>
				<?php
						foreach ($sg['SharingGroupServer'] as $sgs): ?>
				<tr>
					<td><?php echo h($sgs['Server']['name']); ?></td>
					<td><?php echo h($sgs['Server']['url']); ?></td>
					<td><span class="<?php echo ($sgs['all_orgs'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
				</tr>
				<?php
						endforeach;
				?>
			</table>
		</div>
	<?php
		endif;
	?>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'globalActions', 'menuItem' => 'viewSG'));
?>
