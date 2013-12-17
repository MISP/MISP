<div class="task index">
	<h2>Scheduled Tasks</h2>
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
			<th><?php echo $this->Paginator->sort('type');?></th>
			<th><?php echo $this->Paginator->sort('timer');?></th>
			<th><?php echo $this->Paginator->sort('scheduled_time');?></th>
			<th><?php echo $this->Paginator->sort('recurring');?></th>
			<th><?php echo $this->Paginator->sort('description');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($list as $item):?>
	<tr>
		<td class="short"><?php echo h($item['Task']['id']);?>&nbsp;</td>
		<td class="short"><?php echo h($item['Task']['type']);?>&nbsp;</td>
		<td class="short"><?php echo h($item['Task']['timer']);?>&nbsp;</td>
		<td class="short"><?php echo h($item['Task']['scheduled_time']);?>&nbsp;</td>
		<td class="short">
			<?php 
				if (!$item['Task']['recurring']) echo 'No';
				else echo 'Yes';
			?>
		&nbsp;</td>
		<td><?php echo h($item['Task']['description']);?>&nbsp;</td>
		<td class="short action-links">
			<?php echo $this->Html->link('', array('action' => 'setTask', $item['Task']['id']), array('class' => 'icon-edit', 'title' => 'Edit'));?>
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
<?php 
	echo $this->element('side_menu', array('menuList' => 'task', 'menuItem' => 'index'));
?>