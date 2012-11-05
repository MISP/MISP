<?php $buttonAddStatus = $isAclAdd || (isset($event['Event']['user_id']) && $event['Event']['user_id'] == $me['id']) ? 'button_on':'button_off'; ?>
        <li><?php echo $this->Html->link(__('New Event', true), array('controller' => 'events', 'action' => 'add'), array('id' => $buttonAddStatus,'class' => $buttonAddStatus)); ?></li>
		<li><?php echo $this->Html->link(__('List Events', true), array('controller' => 'events', 'action' => 'index')); ?></li>
		<li><?php echo $this->Html->link(__('List Attributes', true), array('controller' => 'attributes', 'action' => 'index')); ?> </li>
		<li><?php echo $this->Html->link(__('Search Attributes', true), array('controller' => 'attributes', 'action' => 'search')); ?> </li>
		<li><?php echo $this->Html->link(__('Export', true), array('controller' => 'events', 'action' => 'export')); ?></li>

		<li>&nbsp;</li>
		<h3><?php echo __('Global Actions'); ?></h3>
		<li><?php echo $this->Html->link(__('News', true), array('controller' => 'users', 'action' => 'news')); ?> </li>
		<li><?php echo $this->Html->link(__('My Profile', true), array('controller' => 'users', 'action' => 'view', 'me')); ?> </li>
		<li><?php echo $this->Html->link(__('Members List', true), array('controller' => 'users', 'action' => 'memberslist')); ?> </li>
		<li><?php echo $this->Html->link(__('User Guide', true), array('controller' => 'pages', 'action' => 'display', 'documentation')); ?> </li>
		<li><?php echo $this->Html->link(__('Terms & Conditions', true), array('controller' => 'users', 'action' => 'terms')); ?> </li>
		<li><?php echo $this->Html->link(__('Log out', true), array('controller' => 'users', 'action' => 'logout')); ?> </li>

		<?php if ('true' == Configure::read('CyDefSIG.sync')): ?>
		<li>&nbsp;</li>
		<h3><?php echo __('Sync Actions'); ?></h3>
		<li><?php echo $this->Html->link(__('List Servers'), array('controller' => 'servers', 'action' => 'index'));?></li>
        <?php endif; ?>

		<?php if($isAdmin): ?>
		<li>&nbsp;</li>
		<h3><?php echo __('Administration'); ?></h3>
		<li><?php echo $this->Html->link(__('Whitelist', true), array('controller' => 'whitelists', 'action' => 'index', 'admin' => true)); ?> </li>
		<li>&nbsp;</li>
		<li><?php echo $this->Html->link(__('New User', true), array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link(__('List Users', true), array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link(__('New Role', true), array('controller' => 'groups', 'action' => 'add', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link(__('List Roles', true), array('controller' => 'groups', 'action' => 'index', 'admin' => true)); ?> </li>
		<li>&nbsp;</li>
		<h3><?php echo __('Audit'); ?></h3>
		<li><?php echo $this->Html->link(__('List Logs', true), array('controller' => 'logs', 'action' => 'index', 'admin' => true)); ?> </li>
		<li><?php echo $this->Html->link(__('Search Logs', true), array('controller' => 'logs', 'action' => 'admin_search', 'admin' => true)); ?> </li>
		<?php endif;