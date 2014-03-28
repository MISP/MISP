<div class="actions <?php echo $debugMode;?> sideMenu">
	<ul class="nav nav-list">
		<?php 
			switch ($menuList) {
				case 'event': 
					if ($menuItem === 'addAttribute' || 
						$menuItem === 'addAttachment' || 
						$menuItem === 'addIOC' || 
						$menuItem === 'addThreatConnect'
					) {
						// we can safely assume that mayModify is true if comming from these actions, as they require it in the controller and the user has already passed that check
						$mayModify = true;
						if ($isAclPublish) $mayPublish = true;
					}
					?>						
					<li <?php if ($menuItem === 'viewEvent') echo 'class="active"';?>><a href="/events/view/<?php echo $event['Event']['id'];?>">View Event</a></li>
					<li <?php if ($menuItem === 'eventLog') echo 'class="active"';?>><a href="/logs/event_index/<?php echo $event['Event']['id'];?>">View Event History</a></li>
					<?php if ($isSiteAdmin || (isset($mayModify) && $mayModify)): ?>
					<li <?php if ($menuItem === 'editEvent') echo 'class="active"';?>><a href="/events/edit/<?php echo $event['Event']['id'];?>">Edit Event</a></li>
					<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id'])); ?></li>
					<li class="divider"></li>
					<li <?php if ($menuItem === 'addAttribute') echo 'class="active"';?>><a href="/attributes/add/<?php echo $event['Event']['id'];?>">Add Attribute</a></li>
					<li <?php if ($menuItem === 'addAttachment') echo 'class="active"';;?>><a href="/attributes/add_attachment/<?php echo $event['Event']['id'];?>">Add Attachment</a></li>
					<li <?php if ($menuItem === 'addIOC') echo 'class="active"';?>><a href="/events/addIOC/<?php echo $event['Event']['id'];?>">Populate from OpenIOC</a></li>
					<li <?php if ($menuItem === 'addThreatConnect') echo 'class="active"';?>><a href="/attributes/add_threatconnect/<?php echo $event['Event']['id']; ?>">Populate from ThreatConnect</a></li>
					<?php elseif (!isset($mayModify) || !$mayModify): ?>
					<li class="divider"></li>
					<li <?php if ($menuItem === 'proposeAttribute') echo 'class="active"';?>><a href="/shadow_attributes/add/<?php echo $event['Event']['id'];?>">Propose Attribute</a></li>
					<li <?php if ($menuItem === 'proposeAttachment') echo 'class="active"';?>><a href="/shadow_attributes/add_attachment/<?php echo $event['Event']['id'];?>">Propose Attachment</a></li>
					<?php endif; ?>
					<li class="divider"></li>
					<?php if (isset($event['Event']['published']) && 0 == $event['Event']['published'] && ($isAdmin || (isset($mayPublish) && $mayPublish))): ?>
					<li><?php echo $this->Form->postLink('Publish Event', array('action' => 'alert', $event['Event']['id']), null, 'Are you sure this event is complete and everyone should be informed?'); ?></li>
					<li><?php echo $this->Form->postLink('Publish (no email)', array('action' => 'publish', $event['Event']['id']), null, 'Publish but do NOT send alert email? Only for minor changes!'); ?></li>
					<?php endif; ?>
					<li <?php if ($menuItem === 'contact') echo 'class="active"';?>><a href="/events/contact/<?php echo $event['Event']['id'];?>">Contact Reporter</a></li>
					<li><a href="/events/xml/download/<?php echo $event['Event']['id'];?>">Download as XML</a></li>
					<?php if (isset($event['Event']['published']) && $event['Event']['published']): ?>
					<li><a href="/events/downloadOpenIOCEvent/<?php echo $event['Event']['id'];?>">Download as IOC</a></li>
					<li><a href="/events/csv/download/<?php echo $event['Event']['id'];?>/1">Download as CSV</a></li>
					<?php endif; ?>
					<li class="divider"></li>
					<li><a href="/events/index">List Events</a></li>
					<?php if ($isAclAdd): ?>
					<li><a href="/events/add">Add Event</a></li>
					<?php endif;
				break;

				case 'event-collection': ?>
					<li <?php if ($menuItem === 'index') echo 'class="active"';?>><a href="/events/index">List Events</a></li>
					<?php if ($isAclAdd): ?>
					<li <?php if ($menuItem === 'add') echo 'class="active"';?>><a href="/events/add">Add Event</a></li>
					<li <?php if ($menuItem === 'addXML') echo 'class="active"';?>><a href="/events/add_xml">Add MISP XML</a></li>
					<?php endif; ?>
					<li class="divider"></li>
					<li <?php if ($menuItem === 'listAttributes') echo 'class="active"';?>><a href="/attributes/index">List Attributes</a></li>
					<li <?php if ($menuItem === 'searchAttributes' || $menuItem === 'searchAttributes2') echo 'class="active"';?>><a href="/attributes/search">Search Attributes</a></li>
					<?php if ($menuItem == 'searchAttributes2'): ?>
					<li class="divider"></li>
					<li><a href="/events/downloadSearchResult">Download results as XML</a></li>
					<li><a href="/events/csv/download/search">Download results as CSV</a></li>
					<?php endif; ?>
					<li class="divider"></li>
					<li <?php if ($menuItem === 'viewProposals') echo 'class="active"';?>><a href="/shadow_attributes/index">View Proposals</a></li>
					<li <?php if ($menuItem === 'viewProposalIndex') echo 'class="active"';?>><a href="/events/proposalEventIndex">Events with proposals</a></li>
					<li class="divider"></li>
					<li <?php if ($menuItem === 'export') echo 'class="active"';?>><a href="/events/export">Export</a></li>
					<?php if ($isAclAuth): ?>
					<li <?php if ($menuItem === 'automation') echo 'class="active"';?>><a href="/events/automation">Automation</a></li>
					<?php endif;
				break;
					
				case 'regexp': ?>
					<li <?php if ($menuItem === 'index') echo 'class="active"';?>><?php echo $this->Html->link('List Regexp', array('admin' => $isSiteAdmin, 'action' => 'index'));?></li>
					<?php if ($isSiteAdmin): ?>
					<li <?php if ($menuItem === 'add') echo 'class="active"';?>><?php echo $this->Html->link('New Regexp', array('admin' => true, 'action' => 'add'));?></li>
					<li><?php echo $this->Html->link('Perform on existing', array('admin' => true, 'action' => 'clean'));?></li>
					<?php endif;
					if ($menuItem == 'edit'):?> 
					<li class="divider"></li>
					<li class="active"><?php echo $this->Html->link('Edit Regexp', array('admin' => true, 'action' => 'edit', $id));?></li>
					<li><?php echo $this->Form->postLink('Delete Regexp', array('admin' => true, 'action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id));?></li>
					<?php 
					endif;
				break;
					
					case 'whitelist':?>
					<li <?php if ($menuItem === 'index') echo 'class="active"';?>><?php echo $this->Html->link('List Whitelist', array('admin' => $isSiteAdmin, 'action' => 'index'));?></li>
					<?php if ($isSiteAdmin): ?>
					<li <?php if ($menuItem === 'add') echo 'class="active"';?>><?php echo $this->Html->link('New Whitelist', array('admin' => true, 'action' => 'add'));?></li>
					<?php endif;
					if ($menuItem == 'edit'):?> 
					<li class="divider"></li>
					<li class="active"><?php echo $this->Html->link('Edit Whitelist', array('admin' => true, 'action' => 'edit', $id));?></li>
					<li><?php echo $this->Form->postLink('Delete Whitelist', array('admin' => true, 'action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id));?></li>
					<?php 
					endif;
				break;
					
				case 'globalActions':
					if ($menuItem === 'edit' || $menuItem === 'view'): ?>
					<li <?php if ($menuItem === 'edit') echo 'class="active"';?>><?php echo $this->Html->link(__('Edit User', true), array('action' => 'edit', $user['User']['id'])); ?></li>
					<li class="divider"></li>
					<?php endif; ?>
					<li <?php if ($menuItem === 'news') echo 'class="active"';?>><a href="/users/news">News</a></li>
					<li <?php if ($menuItem === 'view') echo 'class="active"';?>><a href="/users/view/me">My Profile</a></li>
					<li <?php if ($menuItem === 'members') echo 'class="active"';?>><a href="/users/memberslist">Members List</a></li>
					<li <?php if ($menuItem === 'roles') echo 'class="active"';?>><a href="/roles/index">Role Permissions</a></li>
					<li <?php if ($menuItem === 'userGuide') echo 'class="active"';?>><a href="/pages/display/doc/general">User Guide</a></li>
					<li <?php if ($menuItem === 'terms') echo 'class="active"';?>><a href="/users/terms">Terms &amp; Conditions</a></li>
					<li <?php if ($menuItem === 'statistics') echo 'class="active"';?>><a href="/users/statistics">Statistics</a></li>
					<?php 
				break;
				
				case 'sync':
					if ($menuItem === 'edit' && $isAdmin): ?>
					<li class="active"><?php if ($isAdmin) echo $this->Html->link('Edit Server', array('controller' => 'servers', 'action' => 'edit')); ?></li>
					<li><?php echo $this->Form->postLink('Delete', array('action' => 'delete', $this->Form->value('Server.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Server.id'))); ?></li>
					<li class="divider"></li>
					<?php endif; ?>
					<li <?php if ($menuItem === 'index') echo 'class="active"';?>><?php echo $this->Html->link('List Servers', array('controller' => 'servers', 'action' => 'index'));?></li>
					<li <?php if ($menuItem === 'add') echo 'class="active"';?>><?php echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add')); ?></li>
					<?php 
				break;	
				
				case 'admin': 
					if ($menuItem === 'editUser' || $menuItem === 'viewUser'): ?>
					<li <?php if ($menuItem === 'viewUser') echo 'class="active"';?>><?php echo $this->Html->link('View User', array('controller' => 'users', 'action' => 'view', 'admin' => true, $id)); ?> </li>
					<li <?php if ($menuItem === 'editUser') echo 'class="active"';?>><?php echo $this->Html->link('Edit User', array('controller' => 'users', 'action' => 'edit', 'admin' => true, $id)); ?> </li>
					<li><?php echo $this->Form->postLink('Delete User', array('admin' => true, 'action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id));?></li>
					<li class="divider"></li>
					<?php endif; 
					if ($isSiteAdmin && $menuItem === 'editRole'): ?>
					<li class="active"><?php echo $this->Html->link('Edit Role', array('controller' => 'roles', 'action' => 'edit', 'admin' => true, $id)); ?> </li>
					<li><?php echo $this->Form->postLink('Delete Role', array('controller' => 'roles', 'admin' => true, 'action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id));?></li>
					<li class="divider"></li>
					<?php endif; 
					if ($isSiteAdmin): ?>
					<li <?php if ($menuItem === 'addUser') echo 'class="active"';?>><?php echo $this->Html->link('New User', array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
					<li <?php if ($menuItem === 'indexUser') echo 'class="active"';?>><?php echo $this->Html->link('List Users', array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
					<li class="divider"></li>
					<li <?php if ($menuItem === 'addRole') echo 'class="active"';?>><?php echo $this->Html->link('New Role', array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
					<?php endif; ?>
					<li <?php if ($menuItem === 'indexRole') echo 'class="active"';?>><?php echo $this->Html->link('List Roles', array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
					<?php if ($isSiteAdmin): ?>
						<li class="divider"></li>
						<li <?php if ($menuItem === 'contact') echo 'class="active"';?>><?php echo $this->Html->link('Contact users', array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
						<li <?php if ($menuItem === 'adminTools') echo 'class="active"';?>><a href="/pages/display/administration">Administrative tools</a></li>
						<li class="divider"></li>
						<?php if (Configure::read('MISP.background_jobs')): ?>
							<li <?php if ($menuItem === 'jobs') echo 'class="active"';?>><a href="/jobs/index">Jobs</a></li>
							<li class="divider"></li>
							<li <?php if ($menuItem === 'tasks') echo 'class="active"';?>><a href="/tasks">Scheduled Tasks</a></li>
						<?php endif; 
					endif;
				break;	
				
				case 'logs': ?>
					<li <?php if ($menuItem === 'index') echo 'class="active"';?>><?php echo $this->Html->link('List Logs', array('admin' => true, 'action' => 'index'));?></li>
					<li <?php if ($menuItem === 'search') echo 'class="active"';?>><?php echo $this->Html->link('Search Logs', array('admin' => true, 'action' => 'search'));?></li>
					<?php 
				break;	
				
				case 'threads': 
				
					if ($menuItem === 'add' || $menuItem === 'view') {
						if (!(empty($thread_id) && empty($target_type))) { ?>
					<li  <?php if ($menuItem === 'view') echo 'class="active"';?>><?php echo $this->Html->link('View Thread', array('controller' => 'threads', 'action' => 'view', $thread_id));?></li>
					<li  <?php if ($menuItem === 'add') echo 'class="active"';?>><?php echo $this->Html->link('Add Post', array('controller' => 'posts', 'action' => 'add', 'thread', $thread_id));?></li>
					<li class="divider"></li>
					<?php 
						}
					}
					if ($menuItem === 'edit') { ?>
						<li><?php echo $this->Html->link('View Thread', array('controller' => 'threads', 'action' => 'view', $thread_id));?></li>
						<li class="active"><?php echo $this->Html->link('Edit Post', array('controller' => 'threads', 'action' => 'view', $id));?></li>
						<li class="divider"></li>
					<?php 
					}
					?>
					<li <?php if ($menuItem === 'index') echo 'class="active"';?>><?php echo $this->Html->link('List Threads', array('controller' => 'threads', 'action' => 'index'));?></li>
					<li <?php if ($menuItem === 'add' && !isset($thread_id)) echo 'class="active"';?>><a href = "<?php echo Configure::read('MISP.baseurl');?>/posts/add">New Thread</a></li>
					<?php 
				break;	
				
				case 'tags': ?>
					<li <?php if ($menuItem === 'index') echo 'class="active"';?>><?php echo $this->Html->link('List Tags', array('action' => 'index'));?></li>
					<?php if ($isAclTagger): ?>
					<li <?php if ($menuItem === 'add') echo 'class="active"';?>><?php echo $this->Html->link('Add Tag', array('action' => 'add'));?></li>
					<?php 
					endif;
					if ($menuItem === 'edit'): 
					?>
					<li class="active"><?php echo $this->Html->link('Search Logs', array('action' => 'edit'));?></li>
					<?php 
					endif;
				break;	
			}
		?>
	</ul>
</div>
