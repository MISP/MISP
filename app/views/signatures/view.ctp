<div class="signatures view">
<h2><?php  __('Signature');?></h2>
	<dl><?php $i = 0; $class = ' class="altrow"';?>
		<dt<?php if ($i % 2 == 0) echo $class;?>><?php __('Id'); ?></dt>
		<dd<?php if ($i++ % 2 == 0) echo $class;?>>
			<?php echo $signature['Signature']['id']; ?>
			&nbsp;
		</dd>
		<dt<?php if ($i % 2 == 0) echo $class;?>><?php __('Event'); ?></dt>
		<dd<?php if ($i++ % 2 == 0) echo $class;?>>
			<?php echo $this->Html->link($signature['Event']['id'], array('controller' => 'events', 'action' => 'view', $signature['Event']['id'])); ?>
			&nbsp;
		</dd>
		<dt<?php if ($i % 2 == 0) echo $class;?>><?php __('Type'); ?></dt>
		<dd<?php if ($i++ % 2 == 0) echo $class;?>>
			<?php echo $signature['Signature']['type']; ?>
			&nbsp;
		</dd>
		<dt<?php if ($i % 2 == 0) echo $class;?>><?php __('Value'); ?></dt>
		<dd<?php if ($i++ % 2 == 0) echo $class;?>>
			<?php echo nl2br(Sanitize::html($signature['Signature']['value'])); ?>
			&nbsp;
		</dd>
	</dl>
</div>
<div class="actions">
	<h3><?php __('Actions'); ?></h3>
	<ul>
	   <?php if ($signature['Event']['org'] == $me['org']): ?>
		<li><?php echo $this->Html->link(__('Edit Signature', true), array('action' => 'edit', $signature['Signature']['id'])); ?> </li>
		<li><?php echo $this->Html->link(__('Delete Signature', true), array('action' => 'delete', $signature['Signature']['id']), null, sprintf(__('Are you sure you want to delete # %s?', true), $signature['Signature']['id'])); ?> </li>
		<li>&nbsp;</li>
		<?php endif; ?>
        <?php echo $this->element('actions_menu'); ?>
	</ul>
</div>
