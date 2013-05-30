<div class="index">
	<div class="actions" style="float:right;">
		<ul><li><?php echo $this->Html->link(__('View the event', true), array('action' => 'view', $eventId)); ?> </li></ul>
	</div>
	<h2>Results of the import: </h2>
	<h3><?php echo count($attributes); ?> attributes created successfully, <?php echo count($fails); ?> indicators could not be mapped and saved. </h3>
	<br /><br />
	<?php
if (0 != count($attributes)): ?>
	<h4>Successfully added attributes:</h4>
	<table cellpadding="0" cellspacing="0">
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
	<table cellpadding="0" cellspacing="0">
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
	<ul>
		<li><?php echo $this->Html->link(__('View Event', true), array('controller' => 'events' ,'action' => 'view', $eventId)); ?> </li>
	</ul>
</div>