<?php echo $this->element('bread_crumbs'); ?>
<div class="roles index">
	<h2><?php echo __('Roles');?></h2>
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
			<th><?php echo $this->Paginator->sort('permission', 'Permission');?></th>
			<th><?php echo $this->Paginator->sort('perm_sync', 'Sync Actions');?></th>
			<th><?php echo $this->Paginator->sort('perm_admin', 'Administration Actions');?></th>
			<th><?php echo $this->Paginator->sort('perm_audit', 'Audit Actions');?></th>
			<th><?php echo $this->Paginator->sort('perm_auth', 'Auth Key Access');?></th>
			<th class="actions"><?php echo __('Actions');?></th>
	</tr><?php
foreach ($list as $item): ?>
	<tr>
		<td class="short"><?php echo $this->Html->link(h($item['Role']['id']), array('admin' => true, 'action' => 'edit', $item['Role']['id'])); ?>&nbsp;</td>
		<td><?php echo h($item['Role']['name']); ?>&nbsp;</td>
		<td class="short"><?php echo h($options[$item['Role']['permission']]); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Role']['perm_sync']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Role']['perm_admin']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Role']['perm_audit']); ?>&nbsp;</td>
		<td class="short"><?php echo h($item['Role']['perm_auth']); ?>&nbsp;</td>
		<td class="short action-links">
			<?php echo $this->Html->link('', array('admin' => true, 'action' => 'edit', $item['Role']['id']), array('class' => 'icon-edit', 'title' => 'Edit')); ?>
			<?php echo $this->Form->postLink('', array('admin' => true, 'action' => 'delete', $item['Role']['id']), array('class' => 'icon-trash', 'title' => 'Delete'), __('Are you sure you want to delete %s?', $item['Role']['name'])); ?>
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
<div class="actions <?php echo $debugMode;?>">
	<ul class="nav nav-list">
		<li><?php echo $this->Html->link('New User', array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link('List Users', array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
		<li class="divider"></li>
		<?php if ($isSiteAdmin): ?>
		<li><?php echo $this->Html->link('New Role', array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
		<?php endif; ?>
		<li class="active"><?php echo $this->Html->link('List Roles', array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
		<?php if ($isSiteAdmin): ?>
		<li class="divider"></li>
		<li><?php echo $this->Html->link('Contact users', array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
		<?php endif; ?>
	</ul>
</div>