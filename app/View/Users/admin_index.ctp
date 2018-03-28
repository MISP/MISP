<div class="users index">
	<h2><?php echo __('Users');?></h2>
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
	<?php
		$tab = "Center";
		$filtered = false;
		if (count($passedArgsArray) > 0) {
			$tab = "Left";
			$filtered = true;
		}
	?>
	<div class="tabMenuFixedContainer" style="display:inline-block;">
		<span class="tabMenuFixed tabMenuFixed<?php echo $tab; ?> tabMenuSides">
			<span id="create-button" title="<?php echo __('Modify filters');?>" role="button" tabindex="0" aria-label="<?php echo __('Modify filters');?>" class="fa fa-search icon-search useCursorPointer" onClick="getPopup('<?php echo h($urlparams);?>', 'admin/users', 'filterUserIndex');"></span>
		</span>
		<?php if ($filtered):
			foreach ($passedArgsArray as $k => $v):?>
				<span class="tabMenuFixed tabMenuFixedElement">
					<?php echo h(ucfirst($k)) . " : " . h($v); ?>
				</span>
			<?php endforeach; ?>
		<span class="tabMenuFixed tabMenuFixedRight tabMenuSides">
			<?php echo $this->Html->link('', array('controller' => 'users', 'action' => 'index', 'admin' => true), array('class' => 'fa fa-remove', 'title' => __('Remove filters')));?>
		</span>
		<?php endif;?>
		<span id="quickFilterButton" role="button" tabindex="0" aria-label="<?php echo __('Filter user index');?>" class="tabMenuFilterFieldButton useCursorPointer" onClick="quickFilter(<?php echo h($passedArgs); ?>, '<?php echo $baseurl . '/users/admin_index'; ?>');">Filter</span>
		<input class="tabMenuFilterField" type="text" id="quickFilterField"></input>
	</div>
	<?php
		echo $this->element('Users/userIndexTable');
	?>
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
	echo $this->element('side_menu', array('menuList' => 'admin', 'menuItem' => 'indexUser'));
