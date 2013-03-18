<div class="attributes index">
	<h2><?php echo __('Attributes');?></h2>
		<?php
if ($isSearch == 1) {
	echo "<h4>Results for all attributes";
	if ($keywordSearch != null) echo " with the value containing \"<b>" . h($keywordSearch) . "</b>\"";
	if ($keywordSearch2 != null) echo " excluding the events \"<b>" . h($keywordSearch2) . "</b>\"";
	if ($categorySearch != "ALL") echo " of category \"<b>" . h($categorySearch) . "</b>\"";
	if ($typeSearch != "ALL") echo " of type \"<b>" . h($typeSearch) . "</b>\"";
	echo ":</h4>";
} ?>
	<table cellpadding="0" cellspacing="0">
	<tr>
			<th><?php echo $this->Paginator->sort('event_id');?></th>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th<?php echo ' title="' . $attrDescriptions['signature']['desc'] . '"';?>>
			<?php echo $this->Paginator->sort('signature');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr>
	<?php
	$currentCount = 0;
foreach ($attributes as $attribute):
	?>
	<tr>
		<td class="short">
			<?php
				echo "<div id = \"" . $attribute['Attribute']['id'] . "\" title = \"".h($attribute['Event']['info'])."\">";
				echo $this->Html->link($attribute['Event']['id'], array('controller' => 'events', 'action' => 'view', $attribute['Event']['id']));
				$currentCount++;
			?>
		</td>
		<td title="<?php echo $categoryDefinitions[$attribute['Attribute']['category']]['desc'];?>" class="short" onclick="document.location ='
		<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
		<?php echo h($attribute['Attribute']['category']); ?>&nbsp;</td>
		<td title="<?php echo $typeDefinitions[$attribute['Attribute']['type']]['desc'];?>" class="short" onclick="document.location ='
		<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
		<?php echo h($attribute['Attribute']['type']); ?>&nbsp;</td>
		<td onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
	<?php
	$sigDisplay = nl2br(($attribute['Attribute']['value']));
	if ('attachment' == $attribute['Attribute']['type'] || 'malware-sample' == $attribute['Attribute']['type']) {
		echo $this->Html->link($sigDisplay, array('controller' => 'attributes', 'action' => 'download', $attribute['Attribute']['id']), array('escape' => FALSE));
	} elseif ('link' == $attribute['Attribute']['type']) {
		if (isset($attribute['Attribute']['ValueNoScript'])) {
			echo $this->Html->link($sigDisplay, nl2br($attribute['Attribute']['valueNoScript']), array('escape' => FALSE));
		} else {
			echo $this->Html->link($sigDisplay, nl2br($attribute['Attribute']['value']), array('escape' => FALSE));
		}
	} else {
		echo $sigDisplay;
	}
	?>&nbsp;</td>
		<td class="short" style="text-align: center;" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
		<?php echo $attribute['Attribute']['to_ids'] ? 'Yes' : 'No'; ?>&nbsp;</td>
		<td class="actions"><?php
	if ($isAdmin || ($isAclModify && $attribute['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $attribute['Event']['org'] == $me['org'])) {
		echo $this->Html->link(__('Edit'), array('action' => 'edit', $attribute['Attribute']['id']), null);
		echo $this->Form->postLink(__('Delete'), array('action' => 'delete', $attribute['Attribute']['id']), null, __('Are you sure you want to delete this attribute?'));
	}
	echo $this->Html->link(__('View'), array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']));
	?>
		</td>
	</tr>
	<?php
endforeach;
	?>
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
		<li><?php echo $this->Html->link(__('Download results as XML'), array('admin' => false, 'controller' => 'events', 'action' => 'downloadSearchResult'));?></li>
		<?php echo $this->element('actions_menu'); ?>
	</ul>
</div>