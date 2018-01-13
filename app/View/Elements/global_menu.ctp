<div id="topBar" class="navbar-wrapper header <?php echo $debugMode;?>">
	<div class="navbar navbar-inverse">
		<div class="navbar-inner">
		  <!-- .btn-navbar is used as the toggle for collapsed navbar content -->
	    <a class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
	      <span class="icon-bar"></span>
	      <span class="icon-bar"></span>
	      <span class="icon-bar"></span>
	    </a>
		<?php if ($me != false ):?>
			<div class="nav-collapse collapse">
				<ul class="nav">
					<?php
						$logo = 'Home';
						if (Configure::read('MISP.home_logo')) $logo = '<img src="' . $baseurl . '/img/custom/' . Configure::read('MISP.home_logo') . '" style="height:24px;">';
					?>
					<li><a href="<?php echo !empty($baseurl) ? $baseurl : '/';?>" style="color:white"><?php echo $logo; ?></a></li>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Event Actions
							<b class="caret"></b>
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

					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Galaxies
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><a href="<?php echo $baseurl;?>/galaxies/index">List Galaxies</a></li>
						</ul>
					</li>


					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Input Filters
							<b class="caret"></b>
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
							<li><a href="<?php echo $baseurl;?>/warninglists/index">List Warninglists</a></li>
						</ul>
					</li>

					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Global Actions
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><a href="<?php echo $baseurl;?>/news">News</a></li>
							<li><a href="<?php echo $baseurl;?>/users/view/me">My Profile</a></li>
							<li><a href="<?php echo $baseurl;?>/users/dashboard">Dashboard</a></li>
						<?php
							if ($isAclSharingGroup || empty(Configure::read('Security.hide_organisation_index_from_users'))):
						?>
								<li><a href="<?php echo $baseurl;?>/organisations/index">Organisations</a></li>
						<?php
							endif;
						?>
							<li><a href="<?php echo $baseurl;?>/roles/index">Role Permissions</a></li>
							<li class="divider"></li>
							<li><a href="<?php echo $baseurl;?>/objectTemplates/index">List Object Templates</a></li>
							<li class="divider"></li>
							<li><a href="<?php echo $baseurl;?>/sharing_groups/index">List Sharing Groups</a></li>
							<?php if ($isAclSharingGroup): ?>
							<li><a href="<?php echo $baseurl;?>/sharing_groups/add">Add Sharing Group</a></li>
							<?php endif; ?>
							<li class="divider"></li>
							<li><a href="<?php echo $baseurl;?>/pages/display/doc/quickstart">User Guide</a></li>
							<li><a href="<?php echo $baseurl;?>/users/terms">Terms &amp; Conditions</a></li>
							<li><a href="<?php echo $baseurl;?>/users/statistics">Statistics</a></li>
							<li class="divider"></li>
							<li><a href="<?php echo $baseurl;?>/threads/index">List Discussions</a></li>
							<li><a href="<?php echo $baseurl;?>/posts/add">Start Discussion</a></li>
						</ul>
					</li>

					<?php if ($isAclSync || $isAdmin): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Sync Actions
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><a href="<?php echo $baseurl;?>/servers/index">List Servers</a></li>
							<?php if ($isSiteAdmin): ?>
								<li><a href="<?php echo $baseurl;?>/feeds/index">List Feeds</a></li>
							<?php endif;?>
						</ul>
					</li>
					<?php endif;?>

					<?php if ($isAdmin || $isSiteAdmin): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Administration
							<b class="caret"></b>
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
							<?php if ($isSiteAdmin): ?>
							<li><a href="<?php echo $baseurl;?>/admin/roles/add">Add Role</a></li>
							<?php endif; ?>
							<?php if ($isSiteAdmin): ?>
								<li class="divider"></li>
								<li><a href="<?php echo $baseurl;?>/servers/serverSettings">Server settings</a></li>
								<?php if (Configure::read('MISP.background_jobs')): ?>
									<li class="divider"></li>
									<li><a href="<?php echo $baseurl;?>/jobs/index">Jobs</a></li>
									<li class="divider"></li>
									<li><a href="<?php echo $baseurl;?>/tasks">Scheduled Tasks</a></li>
								<?php endif; ?>
								<?php if (Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin): ?>
									<li class="divider"></li>
									<li><a href="<?php echo $baseurl;?>/eventBlacklists/add">Blacklist Event</a></li>
									<li><a href="<?php echo $baseurl;?>/eventBlacklists">Manage Event Blacklists</a></li>
								<?php endif; ?>
								<?php if (Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin): ?>
									<li class="divider"></li>
									<li><a href="<?php echo $baseurl;?>/orgBlacklists/add">Blacklist Organisation</a></li>
									<li><a href="<?php echo $baseurl;?>/orgBlacklists">Manage Org Blacklists</a></li>
								<?php endif; ?>
							<?php endif; ?>
						</ul>
					</li>
					<?php endif; ?>

					<?php if ($isAclAudit): ?>
					<li class="dropdown">
						<a class="dropdown-toggle" data-toggle="dropdown" href="#">
							Audit
							<b class="caret"></b>
						</a>
						<ul class="dropdown-menu">
							<li><a href="<?php echo $baseurl;?>/admin/logs/index">List Logs</a></li>
							<li><a href="<?php echo $baseurl;?>/admin/logs/search">Search Logs</a></li>
						</ul>
					</li>
					<?php endif;?>
				</ul>
			</div>
			<div class="nav-collapse collapse pull-right">
				<ul class="nav">
					<li>
						<a href="<?php echo $baseurl;?>/" id="smallLogo" style="font-weight:bold;">
							<span class="logoBlueStatic">MISP</span>
						</a>
					</li>
					<li>
						<a href="<?php echo $baseurl;?>/users/view/me" class="white" style="padding-left:0px;padding-right:5px;" title="<?php echo h($me['email']);?>"><?php echo $loggedInUserName;?></a>
					</li>
					<li>
						<a href="<?php echo $baseurl;?>/users/dashboard" style="padding-left:0px;padding-right:0px;">
							<span class="notification-<?php echo ($notifications['total'] > 0) ? 'active' : 'passive';?>"><span style="float:left;margin-top:3px;margin-right:3px;margin-left:3px;" class="icon-envelope icon-white" title="Dashboard" role="button" tabindex="0" aria-label="Dashboard"></span></span>
						</a>
					</li>
					<?php if (!$externalAuthUser || !Configure::read('Plugin.CustomAuth_disable_logout')): ?>
						<li><a href="<?php echo $baseurl;?>/users/logout">Log out</a></li>
					<?php elseif (Configure::read('Plugin.CustomAuth_custom_logout')): ?>
						<li><a href="<?php echo h(Configure::read('Plugin.CustomAuth_custom_logout'));?>">Log out</a></li>
					<?php endif; ?>
				</ul>
			</div>
		<?php endif;?>
		</div>
	</div>
</div>
