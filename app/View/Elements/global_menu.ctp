<div class="navbar-wrapper">

	<div class="navbar navbar-inverse">
		<div class="navbar-inner">
			<div class="nav-collapse collapse">
				<ul class="nav">
					<li class="active"><?php echo $this->Html->link('home', '/');?></li>

					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Event Actions
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<?php if ($isAclAdd): ?>
							<li><?php echo $this->Html->link(__('New Event', true), array('controller' => 'events', 'action' => 'add')); ?></li>
							<?php endif; ?>
							<li><?php echo $this->Html->link(__('List Events', true), array('controller' => 'events', 'action' => 'index')); ?></li>
							<li class="divider"></li>
							<li><?php echo $this->Html->link(__('List Attributes', true), array('controller' => 'attributes', 'action' => 'index')); ?> </li>
							<li><?php echo $this->Html->link(__('Search Attributes', true), array('controller' => 'attributes', 'action' => 'search')); ?> </li>
							<li class="divider"></li>
							<li><?php echo $this->Html->link(__('Export', true), array('controller' => 'events', 'action' => 'export')); ?> </li>
							<?php if ($isAclAuth): ?>
							<li><?php echo $this->Html->link(__('Automation', true), array('controller' => 'events', 'action' => 'automation')); ?></li>
							<?php endif;?>
						</ul>
					</li>

					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Input Filters
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">

							<li><?php echo $this->Html->link(__('Import Blacklist', true), array('controller' => 'blacklists', 'action' => 'index')); ?> </li>
							<li><?php echo $this->Html->link(__('Import Regexp', true), array('controller' => 'regexp', 'action' => 'index')); ?> </li>
							<li><?php echo $this->Html->link(__('Signature Whitelist', true), array('controller' => 'whitelists', 'action' => 'index')); ?> </li>
						</ul>
					</li>

					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Global Actions
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><?php echo $this->Html->link(__('News', true), array('controller' => 'users', 'action' => 'news', 'plugin' => false)); ?> </li>
							<li><?php echo $this->Html->link(__('My Profile', true), array('controller' => 'users', 'action' => 'view', 'me', 'plugin' => false)); ?> </li>
							<li><?php echo $this->Html->link(__('Members List', true), array('controller' => 'users', 'action' => 'memberslist', 'plugin' => false)); ?> </li>
							<li><?php echo $this->Html->link(__('User Guide', true), array('controller' => 'pages', 'action' => 'display', 'documentation', 'plugin' => false)); ?> </li>
							<li><?php echo $this->Html->link(__('Terms & Conditions', true), array('controller' => 'users', 'action' => 'terms', 'plugin' => false)); ?> </li>
							<li class="divider"></li>
							<li><?php echo $this->Html->link(__('Log out', true), array('controller' => 'users', 'action' => 'logout', 'plugin' => false)); ?> </li>
						</ul>
					</li>

					<?php
if (('true' == Configure::read('CyDefSIG.sync')) && ($isAclSync || $isAdmin)): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Sync Actions
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><?php echo $this->Html->link(__('List Servers'), array('controller' => 'servers', 'action' => 'index', 'plugin' => false));?></li>
						</ul>
					</li>
					<?php
endif;
if($isAdmin || $isSiteAdmin): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Administration
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><?php echo $this->Html->link(__('New User', true), array('controller' => 'users', 'action' => 'add', 'admin' => true, 'plugin' => false)); ?> </li>
							<li><?php echo $this->Html->link(__('List Users', true), array('controller' => 'users', 'action' => 'index', 'admin' => true, 'plugin' => false)); ?> </li>
							<li class="divider"></li>
							<?php if($isSiteAdmin): ?>
							<li><?php echo $this->Html->link(__('New Role', true), array('controller' => 'roles', 'action' => 'add', 'admin' => true, 'plugin' => false)); ?> </li>
							<?php endif; ?>
							<li><?php echo $this->Html->link(__('List Roles', true), array('controller' => 'roles', 'action' => 'index', 'admin' => true, 'plugin' => false)); ?> </li>
							<?php if($isSiteAdmin): ?>
							<li class="divider"></li>
							<li><?php echo $this->Html->link(__('Contact users', true), array('controller' => 'users', 'action' => 'email', 'admin' => true, 'plugin' => false)); ?> </li>
							<?php endif; ?>
						</ul>
					</li>
					<?php
endif;
if($isAclAudit): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Audit
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><?php echo $this->Html->link(__('List Logs', true), array('controller' => 'logs', 'action' => 'index', 'admin' => true, 'plugin' => false)); ?> </li>
							<li><?php echo $this->Html->link(__('Search Logs', true), array('controller' => 'logs', 'action' => 'admin_search', 'admin' => true, 'plugin' => false)); ?> </li>
						</ul>
					</li>
					<?php
endif;?>
				</ul>
			</div>
		</div>
	</div>
</div>