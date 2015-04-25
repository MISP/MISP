<div class="actions <?php echo $debugMode;?> sideMenu">
	<ul class="nav nav-list">
		<?php 
			switch ($menuList) {
				case 'event': 
					if ($menuItem === 'addAttribute' || 
						$menuItem === 'addAttachment' || 
						$menuItem === 'addIOC' || 
						$menuItem === 'addThreatConnect' ||
						$menuItem === 'populateFromtemplate'
					) {
						// we can safely assume that mayModify is true if comming from these actions, as they require it in the controller and the user has already passed that check
						$mayModify = true;
						if ($isAclPublish) $mayPublish = true;
					}
					?>
					<li id='liviewEvent'><a href="/events/view/<?php echo $event['Event']['id'];?>">View Event</a></li>
					<li id='lieventLog'><a href="/logs/event_index/<?php echo $event['Event']['id'];?>">View Event History</a></li>
					<li class="divider"></li>
					<?php if ($isSiteAdmin || (isset($mayModify) && $mayModify)): ?>
					<li id='lieditEvent'><a href="/events/edit/<?php echo $event['Event']['id'];?>">Edit Event</a></li>
					<li><?php echo $this->Form->postLink('Delete Event', array('action' => 'delete', $event['Event']['id']), null, __('Are you sure you want to delete # %s?', $event['Event']['id'])); ?></li>
					<li id='liaddAttribute'><a href="/attributes/add/<?php echo $event['Event']['id'];?>">Add Attribute</a></li>
					<li id='liaddAttachment'><a href="/attributes/add_attachment/<?php echo $event['Event']['id'];?>">Add Attachment</a></li>
					<li id='liaddIOC'><a href="/events/addIOC/<?php echo $event['Event']['id'];?>">Populate from OpenIOC</a></li>
					<li id='liaddThreatConnect'><a href="/attributes/add_threatconnect/<?php echo $event['Event']['id']; ?>">Populate from ThreatConnect</a></li>
					<?php if ($menuItem === 'populateFromtemplate'): ?>
							<li class="active"><a href="/templates/populateEventFromTemplate/<?php echo $template_id . '/' . $event['Event']['id']; ?>">Populate From Template</a></li>
						<?php endif; ?>
					<?php endif; ?>
					<?php if (($isSiteAdmin && (!isset($mayModify) || !$mayModify)) || (!isset($mayModify) || !$mayModify)): ?>
					<li id='liproposeAttribute'><a href="/shadow_attributes/add/<?php echo $event['Event']['id'];?>">Propose Attribute</a></li>
					<li id='liproposeAttachment'><a href="/shadow_attributes/add_attachment/<?php echo $event['Event']['id'];?>">Propose Attachment</a></li>
					<?php endif; ?>
					<li class="divider"></li>
					<?php 
						$publishButtons = ' style="display:none;"';
						$exportButtons = ' style="display:none;"';
						if (isset($event['Event']['published']) && 0 == $event['Event']['published'] && ($isAdmin || (isset($mayPublish) && $mayPublish))) $publishButtons = "";
						if (isset($event['Event']['published']) && $event['Event']['published']) $exportButtons = "";
					?>
					<li<?php echo $publishButtons; ?> class="publishButtons"><a href="#" onClick="publishPopup('<?php echo $event['Event']['id']; ?>', 'alert')">Publish Event</a></li>
					<li<?php echo $publishButtons; ?> class="publishButtons"><a href="#" onClick="publishPopup('<?php echo $event['Event']['id']; ?>', 'publish')">Publish (no email)</a></li>

					<li id='licontact'><a href="/events/contact/<?php echo $event['Event']['id'];?>">Contact Reporter</a></li>
					<li><a onClick="getPopup('<?php echo $event['Event']['id']; ?>', 'events', 'exportChoice');" style="cursor:pointer;">Download as...</a></li>
					<li class="divider"></li>
					<li><a href="/events/index">List Events</a></li>
					<?php if ($isAclAdd): ?>
					<li><a href="/events/add">Add Event</a></li>
					<?php endif;
				break;

				case 'event-collection': ?>
					<li id='liindex'><a href="/events/index">List Events</a></li>
					<?php if ($isAclAdd): ?>
					<li id='liadd'><a href="/events/add">Add Event</a></li>
					<li id='liaddXML'><a href="/events/add_xml">Add MISP XML</a></li>
					<?php endif; ?>
					<li class="divider"></li>
					<li id='lilistAttributes'><a href="/attributes/index">List Attributes</a></li>
					<li id='lisearchAttributes' || $menuItem === 'searchAttributes2'><a href="/attributes/search">Search Attributes</a></li>
					<?php if ($menuItem == 'searchAttributes2'): ?>
					<li class="divider"></li>
					<li><a href="/events/downloadSearchResult">Download results as XML</a></li>
					<li><a href="/events/csv/download/search">Download results as CSV</a></li>
					<?php endif; ?>
					<li class="divider"></li>
					<li id='liviewProposals'><a href="/shadow_attributes/index">View Proposals</a></li>
					<li id='liviewProposalIndex'><a href="/events/proposalEventIndex">Events with proposals</a></li>
					<li class="divider"></li>
					<li id='liexport'><a href="/events/export">Export</a></li>
					<?php if ($isAclAuth): ?>
					<li id='liautomation'><a href="/events/automation">Automation</a></li>
					<?php endif;
				break;
					
				case 'regexp': ?>
					<li id='liindex'><?php echo $this->Html->link('List Regexp', array('admin' => $isSiteAdmin, 'action' => 'index'));?></li>
					<?php if ($isSiteAdmin): ?>
					<li id='liadd'><?php echo $this->Html->link('New Regexp', array('admin' => true, 'action' => 'add'));?></li>
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
					<li id='liindex'><?php echo $this->Html->link('List Whitelist', array('admin' => $isSiteAdmin, 'action' => 'index'));?></li>
					<?php if ($isSiteAdmin): ?>
					<li id='liadd'><?php echo $this->Html->link('New Whitelist', array('admin' => true, 'action' => 'add'));?></li>
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
					<li id='liedit'><?php echo $this->Html->link(__('Edit User', true), array('action' => 'edit', $user['User']['id'])); ?></li>
					<li class="divider"></li>
					<?php endif; ?>
					<li id='linews'><a href="/users/news">News</a></li>
					<li id='liview'><a href="/users/view/me">My Profile</a></li>
					<li id='limembers'><a href="/users/memberslist">Members List</a></li>
					<li id='liindexOrg'><a href="/organisations/index">List Organisations</a></li>
					<?php if ($menuItem === 'viewOrg'): ?>
						<li class="active"><a href="/organisations/view/<?php echo $id;?>">View Organisation</a></li>
					<?php endif;?>
					<li id='liroles'><a href="/roles/index">Role Permissions</a></li>
					<li class="divider"></li>
					<?php if ($menuItem === 'editSG' || ($menuItem == 'viewSG' && $mayModify)): ?>
						<li id='lieditSG'><a href="/sharing_groups/edit/<?php echo $id; ?>">Edit Sharing Group</a></li>
						<li id='liviewSG'><a href="/sharing_groups/view/<?php echo $id;?>">View Sharing Group</a></li>
					<?php endif; ?>
					<li id='liindexSG'><a href="/sharing_groups/index">List Sharing Groups</a></li>
					<li id='liaddSG'><a href="/sharing_groups/add">Add Sharing Group</a></li>
					<li class="divider"></li>
					<li id='liuserGuide'><a href="/pages/display/doc/general">User Guide</a></li>
					<li id='literms'><a href="/users/terms">Terms &amp; Conditions</a></li>
					<li id='listatistics'><a href="/users/statistics">Statistics</a></li>
					<?php 
				break;
				
				case 'sync':
					if ($menuItem === 'edit' && $isAdmin): ?>
					<li class="active"><?php if ($isAdmin) echo $this->Html->link('Edit Server', array('controller' => 'servers', 'action' => 'edit')); ?></li>
					<li><?php echo $this->Form->postLink('Delete', array('action' => 'delete', $this->Form->value('Server.id')), null, __('Are you sure you want to delete # %s?', $this->Form->value('Server.id'))); ?></li>
					<li class="divider"></li>
					<?php endif; ?>
					<li id='liindex'><?php echo $this->Html->link('List Servers', array('controller' => 'servers', 'action' => 'index'));?></li>
					<li id='liadd'><?php echo $this->Html->link(__('New Server'), array('controller' => 'servers', 'action' => 'add')); ?></li>
					<?php 
				break;	
					
				case 'admin': 
					if ($menuItem === 'editUser' || $menuItem === 'viewUser'): ?>
					<li id='liviewUser'><?php echo $this->Html->link('View User', array('controller' => 'users', 'action' => 'view', 'admin' => true, $id)); ?> </li>
					<li id='lieditUser'><?php echo $this->Html->link('Edit User', array('controller' => 'users', 'action' => 'edit', 'admin' => true, $id)); ?> </li>
					<li><?php echo $this->Form->postLink('Delete User', array('admin' => true, 'action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id));?></li>
					<li class="divider"></li>
					<?php endif; 
					if ($isSiteAdmin && $menuItem === 'editRole'): ?>
					<li class="active"><?php echo $this->Html->link('Edit Role', array('controller' => 'roles', 'action' => 'edit', 'admin' => true, $id)); ?> </li>
					<li><?php echo $this->Form->postLink('Delete Role', array('controller' => 'roles', 'admin' => true, 'action' => 'delete', $id), null, __('Are you sure you want to delete # %s?', $id));?></li>
					<li class="divider"></li>
					<?php endif; 
					if ($isSiteAdmin): ?>
					<li id='liaddUser'><?php echo $this->Html->link('Add User', array('controller' => 'users', 'action' => 'add', 'admin' => true)); ?> </li>
					<li id='liindexUser'><?php echo $this->Html->link('List Users', array('controller' => 'users', 'action' => 'index', 'admin' => true)); ?> </li>
					<li id='licontact'><?php echo $this->Html->link('Contact Users', array('controller' => 'users', 'action' => 'email', 'admin' => true)); ?> </li>
					<li class="divider"></li>
					<li id='liaddOrg'><a href="/admin/organisations/add">Add Organisation</a></li>
					<?php if ($menuItem === 'editOrg' || $menuItem === 'viewOrg'): ?>
						<li id='lieditOrg'><a href="/admin/organisations/edit/<?php echo $id;?>">Edit Organisation</a></li>
					<?php endif;?>
					<?php if ($menuItem === 'editOrg' || $menuItem === 'viewOrg'): ?>
						<li id='liviewOrg'><a href="/organisations/view/<?php echo $id;?>">View Organisation</a></li>
					<?php endif;?>
					<li id='liindexOrg'><a href="/organisations/index">List Organisations</a></li>
					<li class="divider"></li>
					<li id='liaddRole'><?php echo $this->Html->link('Add Role', array('controller' => 'roles', 'action' => 'add', 'admin' => true)); ?> </li>
					<?php endif; ?>
					<li id='liindexRole'><?php echo $this->Html->link('List Roles', array('controller' => 'roles', 'action' => 'index', 'admin' => true)); ?> </li>
					<?php if ($isSiteAdmin): ?>
						<li class="divider"></li>
						<li id='liadminTools'><a href="/pages/display/administration">Administrative Tools</a></li>
						<li id='liserverSettings'><a href="/servers/serverSettings">Server Settings</a></li>
						<li class="divider"></li>
						<?php if (Configure::read('MISP.background_jobs')): ?>
							<li id='lijobs'><a href="/jobs/index">Jobs</a></li>
							<li class="divider"></li>
							<li id='litasks'><a href="/tasks">Scheduled Tasks</a></li>
						<?php endif; 
					endif;
				break;	
				
				case 'logs': ?>
					<li id='liindex'><?php echo $this->Html->link('List Logs', array('admin' => true, 'action' => 'index'));?></li>
					<li id='lisearch'><?php echo $this->Html->link('Search Logs', array('admin' => true, 'action' => 'search'));?></li>
					<?php 
				break;	
				
				case 'threads': 
				
					if ($menuItem === 'add' || $menuItem === 'view') {
						if (!(empty($thread_id) && empty($target_type))) { ?>
					<li  id='view'><?php echo $this->Html->link('View Thread', array('controller' => 'threads', 'action' => 'view', $thread_id));?></li>
					<li  id='add'><?php echo $this->Html->link('Add Post', array('controller' => 'posts', 'action' => 'add', 'thread', $thread_id));?></li>
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
					<li id='liindex'><?php echo $this->Html->link('List Threads', array('controller' => 'threads', 'action' => 'index'));?></li>
					<li id='liadd'><a href = "<?php echo Configure::read('MISP.baseurl');?>/posts/add">New Thread</a></li>
					<?php 
				break;	
				
				case 'tags': ?>
					<li id='liindex'><?php echo $this->Html->link('List Tags', array('action' => 'index'));?></li>
					<?php if ($isAclTagger): ?>
					<li id='liadd'><?php echo $this->Html->link('Add Tag', array('action' => 'add'));?></li>
					<?php 
					endif;
					if ($menuItem === 'edit'): 
					?>
					<li class="active"><?php echo $this->Html->link('Edit Tag', array('action' => 'edit'));?></li>
					<?php 
					endif;
				break;	
				
				case 'templates': ?>
					<li id='liindex'><a href="/templates/index">List Templates</a></li>
					<?php if ($isSiteAdmin || $isAclTemplate): ?>
					<li id='liadd'><a href="/templates/add">Add Template</a></li>
					<?php 
					endif;
					if (($menuItem === 'view' || $menuItem === 'edit')): 
					?>
					<li id='liview'><a href="/templates/view/<?php echo $id; ?>">View Template</a></li>
					<?php if ($mayModify): ?>
					<li id='liedit'><a href="/templates/edit/<?php echo $id; ?>">Edit Template</a></li>
					<?php
					endif; 
					endif;
				break;	
			}
		?>
	</ul>
</div>
<script type="text/javascript">
$(document).ready(function() {
	$('#li<?php echo h($menuItem); ?>').addClass("active");
});
</script>