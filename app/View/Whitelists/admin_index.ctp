<div class="whitelist index">
	<h2>Import Whitelist</h2>
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
			<th><?php echo $this->Paginator->sort('id');?></th>
			<th><?php echo $this->Paginator->sort('name');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($list as $item):?>
	<tr>
		<td class="short"><?php echo h($item['Whitelist']['id']);?>&nbsp;</td>
		<td><?php echo h($item['Whitelist']['name']);?>&nbsp;</td>
		<td class="short action-links">
			<?php echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $item['Whitelist']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));?>
			<?php echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $item['Whitelist']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete "%s"?', $item['Whitelist']['name']));?>
		</td>
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
		<li class="active"><?php echo $this->Html->link('List Whitelist', array('admin' => true, 'action' => 'index'));?></li>
		<li><?php echo $this->Html->link('New Whitelist', array('admin' => true, 'action' => 'add'));?></li>
	</ul>
</div>