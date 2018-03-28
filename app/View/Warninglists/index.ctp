<div class="taxonomies index">
	<h2><?php echo __('Warninglists');?></h2>
	<div>
		<ul class="pagination">
			<?php
			$this->Paginator->options(array(
				'update' => '.span12',
				'evalScripts' => true,
				'before' => '$(".progress").show()',
				'complete' => '$(".progress").hide()',
			));

			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'class' => 'page-link', 'currentClass' => 'page-link', 'currentTag' => 'span', 'currentClass' => 'p-active'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span', 'disabledClass' => 'page-link'));
			?>
		</ul>
	</div>
	<div id="hiddenFormDiv">
	<?php
		if ($isSiteAdmin) {
			echo $this->Form->create('Warninglist', array('url' => '/warninglists/toggleEnable'));
			echo $this->Form->input('data', array('label' => false, 'style' => 'display:none;'));
			echo $this->Form->end();
		}
	?>
	</div>
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th><?php echo $this->Paginator->sort('version');?></th>
			<th><?php echo $this->Paginator->sort('description');?></th>
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th>Valid attributes</th>
			<th><?php echo $this->Paginator->sort('warninglist_entry_count', 'Entries');?></th>
			<th><?php echo $this->Paginator->sort('enabled');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($warninglists as $k => $item): ?>
	<tr>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['id']); ?>&nbsp;</td>
		<td ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['name']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['version']); ?>&nbsp;</td>
		<td ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['description']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['type']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['valid_attributes']); ?>&nbsp;</td>
		<td class="short" ondblclick="document.location.href ='<?php echo $baseurl."/warninglists/view/".h($item['Warninglist']['id']);?>'"><?php echo h($item['Warninglist']['warninglist_entry_count']); ?>&nbsp;</td>
		<?php if ($isSiteAdmin): ?>
		<td class="short" id ="checkbox_row_<?php echo h($item['Warninglist']['id']);?>">
			<input class="form-check-input" id="checkBox_<?php echo h($item['Warninglist']['id']); ?>" type="checkbox" onClick="toggleSetting(event, 'warninglist_enable', '<?php echo h($item['Warninglist']['id']); ?>')" <?php echo $item['Warninglist']['enabled'] ? 'checked' : ''; ?>/>
		</td>
		<?php endif;?>
		<td class="short action-links">
			<a href='<?php echo $baseurl."/warninglists/view/". h($item['Warninglist']['id']);?>' class = "fa fa-list" title = "<?php echo __('View');?>"></a>
			<span class="fa fa-trash useCursorPointer" title="<?php echo __('Delete Warninglist');?>" role="button" tabindex="0" aria-label="<?php echo __('Delete warninglist');?>" onClick="deleteObject('warninglists', 'delete', '<?php echo h($item['Warninglist']['id']); ?>', '<?php echo h($item['Warninglist']['id']); ?>');"></span>
		</td>
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
	<div>
		<ul class="pagination">
			<?php
			echo $this->Paginator->prev('&laquo; ' . __('previous'), array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span'));
			echo $this->Paginator->numbers(array('modulus' => 20, 'separator' => '', 'tag' => 'li', 'class' => 'page-link', 'currentClass' => 'page-link', 'currentTag' => 'span', 'currentClass' => 'p-active'));
			echo $this->Paginator->next(__('next') . ' &raquo;', array('tag' => 'li', 'escape' => false, 'class' => 'page-link'), null, array('tag' => 'li', 'class' => 'page-link', 'escape' => false, 'disabledTag' => 'span', 'disabledClass' => 'page-link'));
			?>
		</ul>
	</div>
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'warninglist', 'menuItem' => 'index'));
?>
