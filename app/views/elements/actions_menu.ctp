        <li><?php echo $this->Html->link(__('New Event', true), array('controller' => 'events', 'action' => 'add')); ?></li>
		<li><?php echo $this->Html->link(__('List Events', true), array('controller' => 'events', 'action' => 'index')); ?></li>
		<li><?php echo $this->Html->link(__('List Signatures', true), array('controller' => 'signatures', 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link(__('Search Signatures', true), array('controller' => 'signatures', 'action' => 'search')); ?> </li>
		<li><?php echo $this->Html->link(__('Export', true), array('controller' => 'events', 'action' => 'export')); ?></li>
		
		<li>&nbsp;</li>
		<li><?php echo $this->Html->link(__('My Profile', true), array('controller' => 'users', 'action' => 'view', 'me')); ?> </li>
		<?php if($isAdmin): ?>
		<li>&nbsp;</li>
		<li><?php echo $this->Html->link(__('New User', true), array('controller' => 'users', 'action' => 'add')); ?> </li>
		<li><?php echo $this->Html->link(__('List Users', true), array('controller' => 'users', 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link(__('New Group', true), array('controller' => 'groups', 'action' => 'add')); ?> </li>
		<li><?php echo $this->Html->link(__('List Groups', true), array('controller' => 'groups', 'action' => 'index')); ?> </li>
		<?php endif; ?>