<div class="pagination">
	<ul>
	<?php
		$this->Paginator->options(array(
				'update' => '#elements_div',
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
	<div class="tabMenu tabMenuFiltersBlock noPrint" style="padding-right:0px !important;">
	<span id="filter_header" class="attribute_filter_header">Filters: </span>AAA
</div>
<table class="table table-striped table-hover table-condensed">
	<tr>
		<th class="short"><?php echo $this->Paginator->sort('key');?></th>
		<th><?php echo $this->Paginator->sort('value');?></th>
	</tr>
<?php
	foreach ($list as $item):
?>
		<tr>
			<td class="short"><?php echo h($item['GalaxyElement']['key']); ?>&nbsp;
			</td><td class="short"><?php echo h($item['GalaxyElement']['value']); ?>&nbsp;</td>
		</tr>
	<?php
		endforeach; 
	?>
</table>
<p>
<?php
	echo $this->Paginator->counter(array('format' => __('Page {:page} of {:pages}, showing {:current} records out of {:count} total, starting on record {:start}, ending on {:end}')));
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
<?php echo $this->Js->writeBuffer();
