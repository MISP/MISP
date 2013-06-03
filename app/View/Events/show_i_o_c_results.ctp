<div class="index">
	<h2>Results of the import: </h2>
	<h3><?php echo count($attributes); ?> attributes created successfully, <?php echo count($fails); ?> indicators could not be mapped and saved. </h3>
	<br /><br />
	<?php
if (0 != count($attributes)): ?>
	<h4>Successfully added attributes:</h4>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th>Uuid</th>
			<th>Category</th>
			<th>Type</th>
			<th>Value</th>
	</tr><?php
foreach ($attributes as $attribute): ?>
	<tr>
		<td class="short"><?php echo h($attribute['uuid']); ?>&nbsp;</td>
		<td class="short"><?php echo h($attribute['category']); ?>&nbsp;</td>
		<td class="short"><?php echo h($attribute['type']); ?>&nbsp;</td>
		<td class="short"><?php echo h($attribute['value']); ?>&nbsp;</td>
	</tr><?php
endforeach; ?>
</table>
<?php
endif;?>
<?php
if (isset($fails)):?>
	<br /><br />
	<h4>Failed indicators:</h4>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th>Uuid</th>
			<th>Search term</th>
			<th>Content</th>
	</tr><?php
foreach ($fails as $fail): ?>
	<tr>
		<td class="short"><?php echo h($fail['uuid']); ?>&nbsp;</td>
		<td class="short"><?php echo h($fail['search']); ?>&nbsp;</td>
		<td class="short"><?php echo h($fail['value']); ?>&nbsp;</td>
	</tr><?php
endforeach; ?>
</table><br /><br />
<div class="visualisation">
<h4>Visualisation:</h4>
<?php
endif;
foreach ($graph as $line): ?>
	<div style="white-space:pre-wrap; color: <?php echo ($line[1] ? 'green' : 'red'); ?>"><?php echo h($line[0]); ?>
	</div>
<?php
endforeach; ?>
</div>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('View Event', array('controller' => 'events', 'action' => 'view', $eventId)); ?> </li>
		<?php if ($isSiteAdmin || $mayModify): ?>
		<li><?php echo $this->Html->link('Edit Event', array('controller' => 'events', 'action' => 'edit', $eventId)); ?> </li>
		<li><?php echo $this->Form->postLink('Delete Event', array('controller' => 'events', 'action' => 'delete', $eventId), null, __('Are you sure you want to delete # %s?', $eventId)); ?></li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Add Attribute', array('controller' => 'attributes', 'action' => 'add', $eventId));?> </li>
		<li><?php echo $this->Html->link('Add Attachment', array('controller' => 'attributes', 'action' => 'add_attachment', $eventId));?> </li>
		<li class="active"><?php echo $this->Html->link('Populate event from IOC', array('controller' => 'events', 'action' => 'addIOC', $eventId));?> </li>
		<?php else:	?>
		<li><?php echo $this->Html->link('Propose Attribute', array('controller' => 'shadow_attributes', 'action' => 'add', $eventId));?> </li>
		<li><?php echo $this->Html->link('Propose Attachment', array('controller' => 'shadow_attributes', 'action' => 'add_attachment', $eventId));?> </li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link(__('Contact reporter', true), array('controller' => 'events', 'action' => 'contact', $eventId)); ?> </li>
		<li><?php echo $this->Html->link(__('Download as XML', true), array('controller' => 'events', 'action' => 'xml', 'download', $eventId)); ?></li>
		<li><?php echo $this->Html->link(__('Download as IOC', true), array('controller' => 'events', 'action' => 'downloadOpenIOCEvent', $eventId)); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
		<?php endif; ?>
	</ul>
</div>