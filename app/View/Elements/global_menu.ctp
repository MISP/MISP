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
                            <?php echo __('Event Actions');?>
                            <b class="caret"></b>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a href="<?php echo $baseurl;?>/events/index"><?php echo __('List Events');?></a></li>
                            <?php if ($isAclAdd): ?>
                            <li><a href="<?php echo $baseurl;?>/events/add"><?php echo __('Add Event');?></a></li>
                            <?php endif; ?>
                            <li><a href="<?php echo $baseurl;?>/attributes/index"><?php echo __('List Attributes');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/attributes/search"><?php echo __('Search Attributes');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/servers/rest"><?php echo __('REST client');?></a></li>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/shadow_attributes/index"><?php echo __('View Proposals');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/events/proposalEventIndex"><?php echo __('Events with proposals');?></a></li>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/tags/index"><?php echo __('List Tags');?></a></li>
                            <?php if ($isAclTagEditor): ?>
                            <li><a href="<?php echo $baseurl;?>/tags/add"><?php echo __('Add Tag');?></a></li>
                            <?php endif; ?>
                            <li><a href="<?php echo $baseurl;?>/taxonomies/index"><?php echo __('List Taxonomies');?></a></li>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/templates/index"><?php echo __('List Templates');?></a></li>
                            <?php if ($isAclTemplate): ?>
                            <li><a href="<?php echo $baseurl;?>/templates/add"><?php echo __('Add Template');?></a></li>
                            <?php endif; ?>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/events/export"><?php echo __('Export');?></a></li>
                            <?php if ($isAclAuth): ?>
                            <li><a href="<?php echo $baseurl;?>/events/automation"><?php echo __('Automation');?></a></li>
                            <?php endif;?>

                        </ul>
                    </li>

                    <li class="dropdown">
                        <a class="dropdown-toggle" data-toggle="dropdown" href="#">
                            <?php echo __('Galaxies');?>
                            <b class="caret"></b>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a href="<?php echo $baseurl;?>/galaxies/index"><?php echo __('List Galaxies');?></a></li>
                        </ul>
                    </li>


                    <li class="dropdown">
                        <a class="dropdown-toggle" data-toggle="dropdown" href="#">
                            <?php echo __('Input Filters');?>
                            <b class="caret"></b>
                        </a>
                        <ul class="dropdown-menu">
                            <?php if ($isAclRegexp): ?>
                            <li><a href="<?php echo $baseurl;?>/admin/regexp/index"><?php echo __('Import Regexp');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/admin/whitelists/index"><?php echo __('Signature Whitelist');?></a></li>
                            <?php endif;?>
                            <?php if (!$isAclRegexp): ?>
                            <li><a href="<?php echo $baseurl;?>/regexp/index"><?php echo __('Import Regexp');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/whitelists/index"><?php echo __('Signature Whitelist');?></a></li>
                            <?php endif;?>
                            <li><a href="<?php echo $baseurl;?>/warninglists/index"><?php echo __('List Warninglists');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/noticelists/index"><?php echo __('List Noticelists');?></a></li>
                        </ul>
                    </li>

                    <li class="dropdown">
                        <a class="dropdown-toggle" data-toggle="dropdown" href="#">
                            <?php echo __('Global Actions');?>
                            <b class="caret"></b>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a href="<?php echo $baseurl;?>/news"><?php echo __('News');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/users/view/me"><?php echo __('My Profile');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/users/dashboard"><?php echo __('Dashboard');?></a></li>
                        <?php
                            if ($isAclSharingGroup || empty(Configure::read('Security.hide_organisation_index_from_users'))):
                        ?>
                                <li><a href="<?php echo $baseurl;?>/organisations/index"><?php echo __('Organisations');?></a></li>
                        <?php
                            endif;
                        ?>
                            <li><a href="<?php echo $baseurl;?>/roles/index"><?php echo __('Role Permissions');?></a></li>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/objectTemplates/index"><?php echo __('List Object Templates');?></a></li>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/sharing_groups/index"><?php echo __('List Sharing Groups');?></a></li>
                            <?php if ($isAclSharingGroup): ?>
                            <li><a href="<?php echo $baseurl;?>/sharing_groups/add"><?php echo __('Add Sharing Group');?></a></li>
                            <?php endif; ?>
                            <li class="divider"></li>
                            <li><a href="https://www.circl.lu/doc/misp/" target="_blank"><?php echo __('User Guide');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/pages/display/doc/categories_and_types"><?php echo __('Categories & Types');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/users/terms"><?php echo __('Terms &amp; Conditions');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/users/statistics"><?php echo __('Statistics');?></a></li>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/threads/index"><?php echo __('List Discussions');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/posts/add"><?php echo __('Start Discussion');?></a></li>
                        </ul>
                    </li>

                    <?php if ($isAclSync || $isAdmin): ?>
                    <li class="dropdown">
                        <a class="dropdown-toggle" data-toggle="dropdown" href="#">
                            <?php echo __('Sync Actions');?>
                            <b class="caret"></b>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a href="<?php echo $baseurl;?>/servers/index"><?php echo __('List Servers');?></a></li>
                            <?php if ($isSiteAdmin): ?>
                                <li><a href="<?php echo $baseurl;?>/feeds/index"><?php echo __('List Feeds');?></a></li>
                            <?php endif;?>
                        </ul>
                    </li>
                    <?php endif;?>

                    <?php if ($isAdmin || $isSiteAdmin): ?>
                    <li class="dropdown">
                        <a class="dropdown-toggle" data-toggle="dropdown" href="#">
                            <?php echo __('Administration');?>
                            <b class="caret"></b>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a href="<?php echo $baseurl;?>/admin/users/index"><?php echo __('List Users');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/admin/users/add"><?php echo __('Add User');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/admin/users/email"><?php echo __('Contact Users');?></a></li>
                            <li class="divider"></li>
                                <li><a href="<?php echo $baseurl;?>/organisations/index"><?php echo __('List Organisations');?></a></li>
                            <?php if ($isSiteAdmin): ?>
                                <li><a href="<?php echo $baseurl;?>/admin/organisations/add"><?php echo __('Add Organisation');?></a></li>
                            <?php endif;?>
                            <li class="divider"></li>
                            <li><a href="<?php echo $baseurl;?>/admin/roles/index"><?php echo __('List Roles');?></a></li>
                            <?php if ($isSiteAdmin): ?>
                            <li><a href="<?php echo $baseurl;?>/admin/roles/add"><?php echo __('Add Role');?></a></li>
                            <?php endif; ?>
                            <?php if ($isSiteAdmin): ?>
                                <li class="divider"></li>
                                <li><a href="<?php echo $baseurl;?>/servers/serverSettings"><?php echo __('Server Settings');?> &<br /><?php echo __('Maintenance');?></a></li>
                                <?php if (Configure::read('MISP.background_jobs')): ?>
                                    <li class="divider"></li>
                                    <li><a href="<?php echo $baseurl;?>/jobs/index"><?php echo __('Jobs');?></a></li>
                                    <li class="divider"></li>
                                    <li><a href="<?php echo $baseurl;?>/tasks"><?php echo __('Scheduled Tasks');?></a></li>
                                <?php endif; ?>
                                <?php if (Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin): ?>
                                    <li class="divider"></li>
                                    <li><a href="<?php echo $baseurl;?>/eventBlacklists/add"><?php echo __('Blacklist Event');?></a></li>
                                    <li><a href="<?php echo $baseurl;?>/eventBlacklists"><?php echo __('Manage Event Blacklists');?></a></li>
                                <?php endif; ?>
                                <?php if (Configure::read('MISP.enableEventBlacklisting') !== false && $isSiteAdmin): ?>
                                    <li class="divider"></li>
                                    <li><a href="<?php echo $baseurl;?>/orgBlacklists/add"><?php echo __('Blacklist Organisation');?></a></li>
                                    <li><a href="<?php echo $baseurl;?>/orgBlacklists"><?php echo __('Manage Org Blacklists');?></a></li>
                                <?php endif; ?>
                            <?php endif; ?>
                        </ul>
                    </li>
                    <?php endif; ?>

                    <?php if ($isAclAudit): ?>
                    <li class="dropdown">
                        <a class="dropdown-toggle" data-toggle="dropdown" href="#">
                            <?php echo __('Audit');?>
                            <b class="caret"></b>
                        </a>
                        <ul class="dropdown-menu">
                            <li><a href="<?php echo $baseurl;?>/admin/logs/index"><?php echo __('List Logs');?></a></li>
                            <li><a href="<?php echo $baseurl;?>/admin/logs/search"><?php echo __('Search Logs');?></a></li>
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
                            <span class="notification-<?php echo ($notifications['total'] > 0) ? 'active' : 'passive';?>"><span style="float:left;margin-top:3px;margin-right:3px;margin-left:3px;" class="icon-envelope icon-white" title="<?php echo __('Dashboard');?>" role="button" tabindex="0" aria-label="<?php echo __('Dashboard');?>"></span></span>
                        </a>
                    </li>
                    <?php if (!$externalAuthUser && !Configure::read('Plugin.CustomAuth_disable_logout')): ?>
                        <li><a href="<?php echo $baseurl;?>/users/logout"><?php echo __('Log out');?></a></li>
                    <?php elseif (Configure::read('Plugin.CustomAuth_custom_logout')): ?>
                        <li><a href="<?php echo h(Configure::read('Plugin.CustomAuth_custom_logout'));?>"><?php echo __('Log out');?></a></li>
                    <?php endif; ?>
                </ul>
            </div>
        <?php endif;?>
        </div>
    </div>
</div>
<input type="hidden" class="keyboardShortcutsConfig" value="/shortcuts/global_menu.json" />
