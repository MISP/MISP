<div class="attributes index">
	<h2>Attributes</h2>
		<?php
if ($isSearch == 1) {
	echo "<h4>Results for all attributes";
	if ($keywordSearch != null) echo " with the value containing \"<b>" . h($keywordSearch) . "</b>\"";
	if ($keywordSearch2 != null) echo " excluding the events \"<b>" . h($keywordSearch2) . "</b>\"";
	if ($categorySearch != "ALL") echo " of category \"<b>" . h($categorySearch) . "</b>\"";
	if ($typeSearch != "ALL") echo " of type \"<b>" . h($typeSearch) . "</b>\"";
	if (isset($orgSearch) && $orgSearch != '' && $orgSearch != null) echo " created by the organisation \"<b>" . h($orgSearch) . "</b>\"";
	echo ":</h4>";
} ?>
	<div class="pagination">
        <ul>
        <?php
        $this->Paginator->options(array(
            'update' => '.span12',
            'evalScripts' => true,
            'before' => '$(".progress").show()',
            'complete' => '$(".progress").hide()',
        ));

            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('event_id');?></th>
			<th><?php echo $this->Paginator->sort('category');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('value');?></th>
			<th<?php echo ' title="' . $attrDescriptions['signature']['desc'] . '"';?>>
			<?php echo $this->Paginator->sort('signature');?></th>
			<th class="actions">Actions</th>
	</tr>
	<?php
	$currentCount = 0;
	if ($isSearch == 1) {

		// sanitize data
		foreach ($keywordArray as &$keywordArrayElement) {
			$keywordArrayElement = h($keywordArrayElement);
		}
		// build the $replacePairs variable used to highlight the keywords
		$replacePairs = $this->Highlight->build_replace_pairs($keywordArray);
	}

foreach ($attributes as $attribute):
	?>
	<tr>
		<td class="short">
			<div id="<?php echo $attribute['Attribute']['id']?>" title="<?php echo h($attribute['Event']['info'])?>"
			 onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
			<?php
				if ($attribute['Event']['orgc'] == $me['org']) {
					echo $this->Html->link($attribute['Event']['id'], array('controller' => 'events', 'action' => 'view', $attribute['Event']['id']), array('class' => 'SameOrgLink'));
				} else {
					echo $this->Html->link($attribute['Event']['id'], array('controller' => 'events', 'action' => 'view', $attribute['Event']['id']));
				}
				$currentCount++;
			?>
			</div>
		</td>
		<td title="<?php echo $categoryDefinitions[$attribute['Attribute']['category']]['desc'];?>" class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
		<?php echo h($attribute['Attribute']['category']); ?>&nbsp;</td>
		<td title="<?php echo $typeDefinitions[$attribute['Attribute']['type']]['desc'];?>" class="short" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
		<?php echo h($attribute['Attribute']['type']); ?>&nbsp;</td>
		<td onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
	<?php
	$sigDisplay = nl2br(h($attribute['Attribute']['value']));
	if ($isSearch == 1 && !empty($replacePairs)) {
		// highlight the keywords if there are any
		$sigDisplay = nl2br($this->Highlight->highlighter($sigDisplay, $replacePairs));
	}
	if ('attachment' == $attribute['Attribute']['type'] || 'malware-sample' == $attribute['Attribute']['type']) {
		echo $this->Html->link($sigDisplay, array('controller' => 'attributes', 'action' => 'download', $attribute['Attribute']['id']), array('escape' => FALSE));
	} elseif ('link' == $attribute['Attribute']['type']) {
		echo $this->Html->link($sigDisplay, nl2br(h($attribute['Attribute']['value'])), array('escape' => FALSE));
	} else {
		echo $sigDisplay;
	}
	?>&nbsp;</td>
		<td class="short" style="text-align: center;" onclick="document.location ='<?php echo $this->Html->url(array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), true);?>';">
		<?php echo $attribute['Attribute']['to_ids'] ? 'Yes' : 'No'; ?>&nbsp;</td>
		<td class="actions"><?php
	if ($isAdmin || ($isAclModify && $attribute['Event']['user_id'] == $me['id']) || ($isAclModifyOrg && $attribute['Event']['org'] == $me['org'])) {
		echo $this->Html->link('', array('action' => 'edit', $attribute['Attribute']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));
		echo $this->Form->postLink('',array('action' => 'delete', $attribute['Attribute']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete this attribute?'));
	}
	echo $this->Html->link('', array('controller' => 'events', 'action' => 'view', $attribute['Attribute']['event_id']), array('class' => 'icon-list-alt', 'title' => 'View'));
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
    ?>
    </p>
    <div class="pagination">
        <ul>
        <?php
            echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'prev disabled', 'escape' => false, 'disabledTag' => 'span'));
            echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'currentClass' => 'active', 'currentTag' => 'span'));
            echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false), null, array('tag' => 'li', 'class' => 'next disabled', 'escape' => false, 'disabledTag' => 'span'));
        ?>
        </ul>
    </div>

</div>
<div class="actions">
	<ul class="nav nav-list">
	<?php
		if ($isSearch == 1){
			$searchClass = 'class="active"';
			$listClass = '';
		} else {
			$searchClass = '';
			$listClass = 'class="active"';
		}
	?>
		<li <?php echo $listClass;?>><?php echo $this->Html->link('List Attributes', array('admin' => false, 'controller' => 'attributes', 'action' => 'index'));?></li>
		<li <?php echo $searchClass;?>><?php echo $this->Html->link('Search Attributes', array('admin' => false, 'controller' => 'attributes', 'action' => 'search'));?></li>
	<?php if ($isSearch == 1): ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link(__('Download results as XML'), array('admin' => false, 'controller' => 'events', 'action' => 'downloadSearchResult'));?></li>
	<?php endif; ?>
	</ul>
</div>