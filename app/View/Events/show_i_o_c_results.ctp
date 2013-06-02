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
<h4>Visualisation:</h4>
<?php
endif;
foreach ($graph as $line): ?>
	<div style="white-space:pre-wrap; color: <?php echo ($line[1] ? 'green' : 'red'); ?>"><?php echo h($line[0]); ?>
	</div>
<?php
endforeach; ?>
</div>
<div class="actions">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link(__('View Event', true), array('controller' => 'events' ,'action' => 'view', $eventId)); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Events', array('controller' => 'events', 'action' => 'index')); ?></li>
		<?php if ($isAclAdd): ?>
		<li><?php echo $this->Html->link('Add Event', array('controller' => 'events', 'action' => 'add')); ?></li>
		<?php endif; ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('List Attributes', array('controller' => 'attributes', 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link('Search Attributes', array('controller' => 'attributes', 'action' => 'search')); ?> </li>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Export', array('controller' => 'events', 'action' => 'export')); ?> </li>
		<?php if ($isAclAuth): ?>
		<li><?php echo $this->Html->link('Automation', array('controller' => 'events', 'action' => 'automation')); ?></li>
		<?php endif;?>
	</ul>
</div>