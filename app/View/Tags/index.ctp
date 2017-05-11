<?php
	$emptyDate = 'Date,Close\n';
	$date = new DateTime();
	$date->modify("-1 day");
	$emptyDate .= $date->format("Y-m-d") . ',0\n';
	$date->modify("+1 day");
	$emptyDate .= $date->format("Y-m-d") . ',0\n';
?>
<div class="tags index">
	<h2><?php echo $favouritesOnly ? 'Your Favourite Tags' : 'Tags';?></h2>
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
	<div id="hiddenFormDiv">
	<?php
		echo $this->Form->create('FavouriteTag', array('url' => '/favourite_tags/toggle'));
		echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
		echo $this->Form->end();
	?>
	</div>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('exportable');?></th>
			<th><?php echo $this->Paginator->sort('hide_tag', 'Hidden');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th>Restricted to</th>
			<th>Taxonomy</th>
			<th>Tagged events</th>
			<th>Tagged attributes</th>
			<th>Activity</th>
			<th>Favourite</th>
			<?php if ($isAclTagEditor): ?>
			<th class="actions"><?php echo __('Actions');?></th>
			<?php endif; ?>
	</tr><?php
foreach ($list as $k => $item): ?>
	<tr>
		<td class="short"><?php echo h($item['Tag']['id']); ?>&nbsp;</td>
		<td class="short"><span class="<?php echo ($item['Tag']['exportable'] ? 'icon-ok' : 'icon-remove'); ?>"></span></td>
		<td class="short"><span class="icon-<?php echo $item['Tag']['hide_tag'] ? 'ok' : 'remove'; ?>"></span></td>
		<td><a href="<?php echo $baseurl . "/events/index/searchtag:" . $item['Tag']['id']; ?>" class="tag" style="background-color: <?php echo h($item['Tag']['colour']); ?>;color:<?php echo $this->TextColour->getTextColour($item['Tag']['colour']); ?>" title="<?php echo isset($item['Tag']['Taxonomy']['expanded']) ? h($item['Tag']['Taxonomy']['expanded']) : h($item['Tag']['name']); ?>"><?php echo h($item['Tag']['name']); ?></a></td>
		<td class="short">
			<?php if ($item['Tag']['org_id']): ?>
				<a href="<?php echo $baseurl . "/organisations/view/" . h($item['Tag']['org_id']); ?>"><?php echo h($item['Organisation']['name']);?></a>
			<?php else: ?>
				&nbsp;
			<?php endif; ?>
		</td>
		<td class="short">
		<?php
			if (isset($item['Tag']['Taxonomy'])):
				echo '<a href="' . $baseurl . '/taxonomies/view/' . h($item['Tag']['Taxonomy']['id']) . '" title="' . (isset($item['Tag']['Taxonomy']['description']) ? h($item['Tag']['Taxonomy']['description']) : h($item['Tag']['Taxonomy']['namespace'])) . '">' . h($item['Tag']['Taxonomy']['namespace']) . '</a>';
			endif;
		?>
		&nbsp;
		</td>
		<td class="shortish"><?php echo h($item['Tag']['count']); ?>&nbsp;</td>
		<td class="shortish"><a href="<?php echo $baseurl . "/attributes/search/attributetag:" . $item['Tag']['id']; ?>"><?php echo h($item['Tag']['attribute_count']); ?></a> </td>
		<td class="shortish">
			<?php echo $this->element('sparkline', array('id' => $item['Tag']['id'], 'csv' => isset($csv[$k]) ? $csv[$k] : $emptyDate)); ?>
		</td>
		<td class="short" id ="checkbox_row_<?php echo h($item['Tag']['id']);?>">
			<input id="checkBox_<?php echo h($item['Tag']['id']); ?>" type="checkbox" onClick="toggleSetting(event, 'favourite_tag', '<?php echo h($item['Tag']['id']); ?>')" <?php echo $item['Tag']['favourite'] ? 'checked' : ''; ?>/>
		</td>
		<?php if ($isAclTagEditor): ?>
		<td class="short action-links">
			<?php echo $this->Html->link('', array('action' => 'edit', $item['Tag']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));?>
			<?php echo $this->Form->postLink('', array('action' => 'delete', $item['Tag']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete "%s"?', $item['Tag']['name']));?>
		</td>
		<?php endif; ?>
	</tr><?php
endforeach; ?>
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
<?php
	$menuItem = $favouritesOnly ? 'indexfav' : 'index';
	echo $this->element('side_menu', array('menuList' => 'tags', 'menuItem' => $menuItem));
