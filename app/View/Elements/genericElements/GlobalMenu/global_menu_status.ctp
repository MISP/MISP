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
