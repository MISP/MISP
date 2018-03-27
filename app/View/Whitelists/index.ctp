<div class="whitelist index">
	<h2><?php echo __('Signature Whitelist');?></h2>
	<p><?php echo __('Regex entries (in the standard php regex /{regex}/{modifier} format) entered below will restrict matching attributes from being included in the IDS flag sensitive exports (such as NIDS exports).');?></p>
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
	<table class="table table-striped table-hover table-condensed">
	<tr>
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
	</tr><?php
foreach ($list as $item):?>
	<tr>
		<td class="short"><?php echo h($item['Whitelist']['id']);?>&nbsp;</td>
		<td><?php echo h($item['Whitelist']['name']);?>&nbsp;</td>
	</tr><?php
endforeach;?>
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
</div>
<?php
	echo $this->element('side_menu', array('menuList' => 'whitelist', 'menuItem' => 'index'));
