<!-- Fixed navbar -->
<nav class="navbar navbar-inverse navbar-fixed-top <?php echo $debugMode;?>">
	<div class="container-fluid">
	<!-- Brand and toggle get grouped for better mobile display -->
	 <div class="navbar-header">
		 <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar" aria-expanded="false" aria-controls="navbar">
			 <span class="sr-only">Toggle navigation</span>
			 <span class="icon-bar"></span>
			 <span class="icon-bar"></span>
			 <span class="icon-bar"></span>
		 </button>
		 <a class="navbar-brand" href="#">
			 <?php
				 $logo = 'Home';
				 if (Configure::read('MISP.home_logo')) {
						 $logo = '<img alt="Brand" "src="'.$baseurl.'/img/custom/'.Configure::read('MISP.home_logo').'" style="height:24px;">';
				 }
				 ?>
		 </a>
	 </div>

	<?php if ($me != false):?>
	<!-- Collect the nav links, forms, and other content for toggling -->
	<div id="navbar" class="navbar-collapse collapse">
			<ul class="nav navbar-nav navbar-left">
				<!-- If the user defined a logo this should apear on the left side of the navbar -->
				<li><a href="<?php echo !empty($baseurl) ? $baseurl : '/';?>" style="color:white"><?php echo $logo; ?></a></li>
				<!-- The "Event Actions" dropdown menu  -->
				<li class="dropdown">
					<a href="#" class="dropdown-toggle" data-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">
						Event Actions <span class="caret"></span>
					</a>
					<ul class="dropdown-menu">
						<li><a href="<?php echo $baseurl;?>/events/index">List Events</a></li>
						<?php if ($isAclAdd): ?>
						<li><a href="<?php echo $baseurl;?>/events/add">Add Event</a></li>
						<?php endif; ?>
						<li><a href="<?php echo $baseurl;?>/attributes/index">List Attributes</a></li>
						<li><a href="<?php echo $baseurl;?>/attributes/search">Search Attributes</a></li>
						<li class="divider"></li>
						<li><a href="<?php echo $baseurl;?>/shadow_attributes/index">View Proposals</a></li>
						<li><a href="<?php echo $baseurl;?>/events/proposalEventIndex">Events with proposals</a></li>
						<li class="divider"></li>
						<li><a href="<?php echo $baseurl;?>/tags/index">List Tags</a></li>
						<?php if ($isAclTagEditor): ?>
						<li><a href="<?php echo $baseurl;?>/tags/add">Add Tag</a></li>
						<?php endif; ?>
						<li><a href="<?php echo $baseurl;?>/taxonomies/index">List Taxonomies</a></li>
						<li class="divider"></li>
						<li><a href="<?php echo $baseurl;?>/templates/index">List Templates</a></li>
						<?php if ($isAclTemplate): ?>
						<li><a href="<?php echo $baseurl;?>/templates/add">Add Template</a></li>
						<?php endif; ?>
						<li class="divider"></li>
						<li><a href="<?php echo $baseurl;?>/events/export">Export</a></li>
						<?php if ($isAclAuth): ?>
						<li><a href="<?php echo $baseurl;?>/events/automation">Automation</a></li>
						<?php endif;?>
					</ul>
				</li>

					<!-- The "Input Filters" dropdown menu  -->
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Input Filters	<span class="caret"></span>
						</a>
						<ul class="dropdown-menu">
							<?php if ($isAclRegexp): ?>
							<li><a href="<?php echo $baseurl;?>/admin/regexp/index">Import Regexp</a></li>
							<li><a href="<?php echo $baseurl;?>/admin/whitelists/index">Signature Whitelist</a></li>
							<?php endif;?>
							<?php if (!$isAclRegexp): ?>
							<li><a href="<?php echo $baseurl;?>/regexp/index">Import Regexp</a></li>
							<li><a href="<?php echo $baseurl;?>/whitelists/index">Signature Whitelist</a></li>
							<?php endif;?>
						</ul>
					</li>

					<!-- The "Global Actions" dropdown menu  -->
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Global Actions <span class="caret"></span>
						</a>
						<ul class="dropdown-menu">
								<li><a href="<?php echo $baseurl;?>/users/view/me">My Profile</a></li>
								<li><a href="<?php echo $baseurl;?>/users/dashboard">Dashboard</a></li>
								<li><a href="<?php echo $baseurl;?>/users/memberslist">Members List</a></li>
								<li><a href="<?php echo $baseurl;?>/organisations/index">Organisations</a></li>
								<li><a href="<?php echo $baseurl;?>/roles/index">Role Permissions</a></li>
								<li class="divider"></li>
								<li><a href="<?php echo $baseurl;?>/sharing_groups/index">List Sharing Groups</a></li>
								<?php if ($isAclSharingGroup): ?>
								<li><a href="<?php echo $baseurl;?>/sharing_groups/add">Add Sharing Group</a></li>
								<?php endif; ?>
								<li class="divider"></li>
								<li><a href="<?php echo $baseurl;?>/pages/display/doc/quickstart">User Guide</a></li>
								<li><a href="<?php echo $baseurl;?>/users/terms">Terms &amp; Conditions</a></li>
								<li><a href="<?php echo $baseurl;?>/users/statistics">Statistics</a></li>
							</ul>
					</li>

					<!-- The "Sync Actions" dropdown menu for admins only -->
					<?php if ($isAclSync || $isAdmin): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Sync Actions <span class="caret"></span>
						</a>
						<ul class="dropdown-menu">
							<li><a href="<?php echo $baseurl;?>/servers/index">List Servers</a></li>
							<li><a href="<?php echo $baseurl;?>/feeds/index">List Feeds</a></li>
						</ul>
					</li>
					<?php endif;?>

					<!-- The "Administration" dropdown menu for admins only -->
					<?php if ($isAdmin || $isSiteAdmin): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Administration <span class="caret"></span>
						</a>
						<ul class="dropdown-menu">
								<li><a href="<?php echo $baseurl;?>/admin/users/index">List Users</a></li>
								<li><a href="<?php echo $baseurl;?>/admin/users/add">Add User</a></li>
								<li><a href="<?php echo $baseurl;?>/admin/users/email">Contact Users</a></li>
								<li class="divider"></li>
									<li><a href="<?php echo $baseurl;?>/organisations/index">List Organisations</a></li>
								<?php if ($isSiteAdmin): ?>
									<li><a href="<?php echo $baseurl;?>/admin/organisations/add">Add Organisation</a></li>
								<?php endif;?>
								<li class="divider"></li>
								<li><a href="<?php echo $baseurl;?>/admin/roles/index">List Roles</a></li>
								<?php if($isSiteAdmin): ?>
								<li><a href="<?php echo $baseurl;?>/admin/roles/add">Add Role</a></li>
								<?php endif; ?>
								<?php if($isSiteAdmin): ?>
									<li class="divider"></li>
									<li><a href="<?php echo $baseurl;?>/pages/display/administration">Administrative tools</a></li>
									<li><a href="<?php echo $baseurl;?>/servers/serverSettings">Server settings</a></li>
									<?php if (Configure::read('MISP.background_jobs')): ?>
										<li class="divider"></li>
										<li><a href="<?php echo $baseurl;?>/jobs/index">Jobs</a></li>
										<li class="divider"></li>
										<li><a href="<?php echo $baseurl;?>/tasks">Scheduled Tasks</a></li>
									<?php endif; ?>
									<?php if (Configure::read('MISP.enableEventBlacklisting') && $isSiteAdmin): ?>
										<li class="divider"></li>
										<li><a href="<?php echo $baseurl;?>/eventBlacklists/add">Blacklist Event</a></li>
										<li><a href="<?php echo $baseurl;?>/eventBlacklists">Manage Event Blacklists</a></li>
									<?php endif; ?>
									<?php if (Configure::read('MISP.enableEventBlacklisting') && $isSiteAdmin): ?>
										<li class="divider"></li>
										<li><a href="<?php echo $baseurl;?>/orgBlacklists/add">Blacklist Organisation</a></li>
										<li><a href="<?php echo $baseurl;?>/orgBlacklists">Manage Org Blacklists</a></li>
									<?php endif; ?>
								<?php endif; ?>
						</ul>
					</li>
					<?php endif; ?>

					<!-- The "Audit" dropdown menu -->
					<?php if ($isAclAudit): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Audit	<span class="caret"></span>
						</a>
						<ul class="dropdown-menu">
							<li><a href="<?php echo $baseurl;?>/admin/logs/index">List Logs</a></li>
							<li><a href="<?php echo $baseurl;?>/admin/logs/search">Search Logs</a></li>
						</ul>
					</li>
					<?php endif;?>

					<!-- The "Discussions" dropdown menu -->
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Discussions <span class="caret"></span>
						</a>
						<ul class="dropdown-menu">
							<li><a href="<?php echo $baseurl;?>/threads/index">List Discussions</a></li>
							<li><a href="<?php echo $baseurl;?>/posts/add">Start Discussion</a></li>
						</ul>
					</li>
				</ul>
			<!-- END OF OPTIONS MENU -->

			<!-- START OF PULL RIGHT MENU -->
			<ul class="nav navbar-nav navbar-right">
					<li>
						<a href="<?php echo $baseurl;?>/users/view/me" title="<?php echo h($me['email']);?>">
							<span class="label label-primary"><?php echo $loggedInUserName;?></span>
						</a>
					</li>
					<li>
						<a href="<?php echo $baseurl;?>/users/dashboard">
							Inbox <span class="badge"><?php echo $notifications['total']?></span>
						</a>
					</li>
					<?php if (!$externalAuthUser || !Configure::read('Plugin.CustomAuth_disable_logout')): ?>
							<li><a href="<?php echo $baseurl;?>/users/logout">Log out</a></li>
						<?php elseif (Configure::read('Plugin.CustomAuth_custom_logout')): ?>
							<li><a href="<?php echo h(Configure::read('Plugin.CustomAuth_custom_logout'));?>">Log out</a></li>
					<?php endif; ?>
			</ul>
			<!-- END OF OF PULL RIGHT MENU -->
		</div>
		<?php endif;?>
	</div>
</nav>
