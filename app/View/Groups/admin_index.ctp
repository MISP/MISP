<div class="groups index">
	<h2><?php echo __('Groups');?></h2>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th><?php echo $this->Paginator->sort('add');?></th>
			<th><?php echo $this->Paginator->sort('modify');?></th>
			<th><?php echo $this->Paginator->sort('publish');?></th>
			<th><?php echo $this->Paginator->sort('full');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	foreach ($groups as $group): ?>
	<tr>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $group['Group']['id']), true) ;?>';">
		<?php echo h($group['Group']['id']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $group['Group']['id']), true) ;?>';">
		<?php echo h($group['Group']['name']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $group['Group']['id']), true) ;?>';">
		<?php echo h($group['Group']['perm_add']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $group['Group']['id']), true) ;?>';">
		<?php echo h($group['Group']['perm_modify']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $group['Group']['id']), true) ;?>';">
		<?php echo h($group['Group']['perm_publish']); ?>&nbsp;</td>
		<td class="short" onclick="document.location ='<?php echo $this->Html->url(array('admin' => true, 'action' => 'view', $group['Group']['id']), true) ;?>';">
		<?php echo h($group['Group']['perm_full']); ?>&nbsp;</td>
		<td class="actions">
			<?php echo $this->Html->link(__('View'), array('admin' => true, 'action' => 'view', $group['Group']['id'])); ?>
			<?php echo $this->Html->link(__('Edit'), array('admin' => true, 'action' => 'edit', $group['Group']['id'])); ?>
			<?php echo $this->Form->postLink(__('Delete'), array('admin' => true, 'action' => 'delete', $group['Group']['id']), null, __('Are you sure you want to delete # %s?', $group['Group']['id'])); ?>
		</td>
	</tr>
<?php endforeach; ?>
	</table>
	<p>
	<?php
	echo $this->Paginator->counter(array(
	'format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')
	));
	?>	</p>

	<div class="paging">
	<?php
		echo $this->Paginator->prev('< ' . __('previous'), array(), null, array('class' => 'prev disabled'));
		echo $this->Paginator->numbers(array('separator' => ''));
		echo $this->Paginator->next(__('next') . ' >', array(), null, array('class' => 'next disabled'));
	?>
	</div>
</div>
<div class="actions">
	<ul>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>

<script type="text/javascript">
$('#button_off').click(function() {
	return false;
});
$('#button_off0').click(function() {
	return false;
});
$('#button_off1').click(function() {
	return false;
});
$('#button_off2').click(function() {
	return false;
});
$('#button_off3').click(function() {
	return false;
});
$('#button_off4').click(function() {
	return false;
});
$('#button_off5').click(function() {
	return false;
});
$('#button_off6').click(function() {
	return false;
});
$('#button_off7').click(function() {
	return false;
});
$('#button_off8').click(function() {
	return false;
});
</script>