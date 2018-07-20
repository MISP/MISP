<div class="actions <?php echo $debugMode;?>">
    <ol class="nav nav-list">
            <li><?php echo $this->Html->link(__('Quick Start'), array('controller' => 'pages', 'action' => 'display', 'doc', 'quickstart')); ?></li>
            <li><?php echo $this->Html->link(__('General Layout'), array('controller' => 'pages', 'action' => 'display', 'doc', 'general')); ?></li>
            <li><?php echo $this->Html->link(__('General Concepts'), array('controller' => 'pages', 'action' => 'display', 'doc', 'concepts')); ?></li>
            <li class="active"><?php echo $this->Html->link(__('User Management and Global actions'), array('controller' => 'pages', 'action' => 'display', 'doc', 'user_management')); ?>
            <ul class="nav nav-list">
                <li><a href="#first_run"><?php echo __('First run of the system');?></a></li>
                <li><a href="#manage"><?php echo __('Managing your account');?></a></li>
                <li><a href="#uptodate"><?php echo __('Staying up to date');?></a></li>
            </ul>
        </li>
        <li><?php echo $this->Html->link(__('Using the system'), array('controller' => 'pages', 'action' => 'display', 'doc', 'using_the_system')); ?></li>
        <li><?php echo $this->Html->link(__('Administration'), array('controller' => 'pages', 'action' => 'display', 'doc', 'administration')); ?></li>
        <li><?php echo $this->Html->link(__('Categories and Types'), array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
    </ol>
</div>
<div class="index">
    <h2><?php echo __('User Management and Global Actions');?></h2>
    <a id="first_run"></a>
    <h3><?php echo __('First run of the system');?>:</h3>
    <?php echo __('When first logging into MISP with the username and password provided by your administrator, there are a number of things that need to be done, before you can start using the system.');?><br><br>
    <ul>
        <li><b><?php echo __('Accepting the Terms of use');?>:</b> <?php echo __('The terms of use are shown immediately after logging in for the first time, make sure to read through this page before clicking "Accept Terms" at the bottom of the page.');?><br /><br /></li>
        <li><b><?php echo __('Changing the password');?>:</b> <?php echo __('After accepting the ToU, you\'ll be prompted to change your password, but keep in mind that it has to be at least 6 characters long, it has to include at least one upper-case and one lower-case character in addition to a digit or a special character. Enter the same password into the confirm password field, before clicking submit to finalise the change.');?><br /><br />
        <p><img src="<?php echo $baseurl;?>/img/doc/password.png" alt = "" title="<?php echo __('Changing the password');?>"></p><br /></li>
        <li><b><?php echo __('Setting up the GnuPG Key');?>:</b> <?php echo __('In order for the system to be able to encrypt the messages that you send through it, it needs to know your GnuPG key. Navigate to the Edit profile view (My Profile on the left -&gt; Edit profile in the top right corner). Paste the key into the GnuPG field and click submit.');?><br /><br /></li>
        <li><b><?php echo __('Subscribing to Auto-alerts');?>:</b> <?php echo __('Turning auto-alerts on will allow the system to send you e-mail notifications about any new public events entered into the system by other users and private events added by members of your organisation. To turn this on, navigate to the Edit profile view (My profile on the left navigation menu -&gt; Edit profile in the top right corner). Tick the auto-alert checkbox and click submit to enable this feature.');?><br /><br />
        <p><img src="<?php echo $baseurl;?>/img/doc/alerts.png" alt = "" title="<?php echo __('Use these checkboxes to subscribe to auto-alerts and contact reporter e-mails.');?>"></p><br /></li>
        <li><b><?php echo __('Subscribing to e-mails sent via the "Contact Reporter" functionality');?>:</b> <?php echo __('This feature is turned on right below the autoalerts and will allow you to receive e-mails addressed to your organisation whenever a user tries to ask about an event that was posted by a user of your organisation. Keep in mind that you can still be addressed by such a request even when this setting is turned off, if someone tries to contact you as the event creator directly or your organisation for an event that you personally have created then you will be notified.');?><br /><br />
        <li><b><?php echo __('Reviewing the Terms &amp; Conditions');?>:</b> T<?php echo __('o review the Terms &amp; Conditions or to read the User Guide, use the appropriate button on the left navigation menu.');?><br /><br /></li>
        <li><b><?php echo __('Making sure that compatibility mode is turned off (IE9&amp;IE10)');?>:</b><?php echo __('Compatibility mode can cause some elements to appear differently than intended or not appear at all. Make sure you have this option turned off.');?></li></ul>
<hr />
<a id="manage"></a><h3><?php echo __('Managing your account');?>:</h3>
<?php echo __('To alter any details regarding your profile, use the "My Profile" menu button to bring up the profile overview and then click on "Edit Profile" in the right upper corner.');?><br>
<ul>
    <li style="list-style: none">
        <p><img src="<?php echo $baseurl;?>/img/doc/edit_user.png" title="<?php echo __('Change any of your profile settings here.');?>"></p><br>
    </li>
    <li><b><?php echo __('Changing your e-mail address');?>:</b> <?php echo __('Your e-mail address serves as both a login name and as a means of communication with other users of the MISP system via the contact reporter feature. To change your e-mail address, just enter the edit profile menu (My profile on the left navigation menu -&gt; Edit profile in the top right corner) and change the field titled Email.');?><br /><br /></li>
    <li><b><?php echo __('Changing the password');?>:</b> <?php echo __('As a next step, change the password provided by your administrator to something of your own choosing. Click on My profile on the left navigation menu, under Global Actions, which will bring up the User view. Click on Edit User on the left navigation menu or Edit Profile in the top right corner. This next screen, allows you to edit your details, including your password, by filling out the password field. Keep in mind that the password has to be at least 6 characters long, has to include at least one upper-case and one lower-case character in addition to a digit or a special character. Enter the same password into the confirm password field, before clicking submit to finalise the change.');?><br /><br /></li>
    <li><b><?php echo __('Subscribing to Auto-alerts');?>:</b> <?php echo __('Turning auto-alerts on will allow the system to send you e-mail notifications about any new public events entered into the system by other users and private events added by members of your organisation. To turn this on, navigate to the Edit profile view (My profile on the left navigation menu -&gt; Edit profile in the top right corner). Tick the auto-alert checkbox and click submit to enable this feature.');?><br /><br /></li>
    <li><b><?php echo __('Subscribing to e-mails sent via the "Contact Reporter" functionality');?>:</b> <?php echo __('Turning this feature on will allow you to receive e-mails addressed to your organisation whenever a user tries to ask about an event that was posted by a user of your organisation. Keep in mind that you can still be addressed by such a request even when this setting is turned off, if someone tries to contact the person that reported an event that you yourself have created.');?><br /><br /></li>
    <li><b><?php echo __('Setting up the GnuPG Key');?>:</b> <?php echo __('In order for the system to be able to encrypt the messages that you send through it, it needs to know your GnuPG key. You can acquire this by clicking on the GnuPG key link at the bottom left of the screen. Copy the entirety of the key and navigate to the Edit profile view (My Profile on the left -&gt; Edit profile in the top right corner). Paste the key into the GnuPG field and click submit.');?><br /><br /></li>
    <li><b><?php echo __('Requesting a new authentication key');?>:</b> <?php echo __('It is possible to make the system generate a new authentication key for you (for example if your previous one gets compromised. This can be accessed by clicking on the My Profile button and then clicking the reset key next to the currently active authentication code. The old key will become invalid when the new one is generated.');?><br /><br />
    <p><img src="<?php echo $baseurl;?>/img/doc/reset.png" alt = "" title="<?php echo __('Clicking on reset will generate a new key for you and invalidate the old one, blocking it from being used.');?>"></p></li></ul>
<hr />
<a id="uptodate"></a><h3><?php echo __('Staying up to date');?>:</h3>
<?php echo __('MISP also provides its users with some information about itself and its users through the links provided in the Global Actions menu.');?><br><br>
<ul>
    <li><b><?php echo __('News');?>:</b> <?php echo __('To read about the news regarding the system itself, click on News on the left menu. This will bring up a list of news items concerning updates and changes to MISP itself.');?><br /><br /></li>
    <li><b><?php echo __('Member statistics');?>:</b> <?php echo __('By using the Attribute Histogram menu button on the left, you can see a quick histogram depicting the distribution of attribute types created by each organisation.');?><br /><br /></li>
    <li><b><?php echo __('User Guide');?>:</b> <?php echo __('The user guide is also accessible via the Global Actions menu. You can find out more about how to use the system by reading this.');?><br /><br /></li>
    <li><b><?php echo __('Terms &amp; Conditions');?>:</b> <?php echo __('It is possible to review the terms &amp; conditions that were shown during the first run of the system by clicking on the terms &amp; conditions link in the Global Actions menu.');?><br /><br /></li>
    <li><b><?php echo __('Statistics');?>:</b> <?php echo __('View statistics about the users and the data contained within this instance.');?>
        <ul>
            <li>
                <b><?php echo __('General Statistics');?>:</b> <?php echo __('View a set of statistics such as the number of Events and Attributes currently in existance on the platform. The number in the bracket shows the number of new items added during this week.');?>
            </li>
            <li>
                <b><?php echo __('Activity Heatmap');?>:</b> <?php echo __('This graph shows a heatmap of all activity related to creating event related data on a day by day basis. By default, the graph shows the sum of the contributions of all organisations, but using the buttons representing each organisation in existance on the platform you can switch to the activity heatmap of a single organisation. If you\'d like to see the activity further back in the past, just use the arrow buttons to navigate the heatmap.');?>
            </li>
        </ul>
    </li>
</ul>
<a id="filters"></a><h3><?php echo __('Inspecting the input filters');?>:</h3>
<?php echo __('All the events and attributes that get entered into MISP will be run through a series of input filters. These are defined by the site administrators or users with special privileges to edit the filters, but every user can take a look at the currently active lists.');?><br><br>
<ul>
    <li><b><?php echo __('Import Regexp');?>:</b> <?php echo __('All Attribute value and Event info fields will be parsed for a set of regular expressions and replaced based on the replacement values contained in this section. This has many uses, such as unifying similar data for better correlation, removing personal data from file-paths or simply for clarity. It is also possible to blacklist data by not defining a replacement for a regular expression.');?> <br /><br /></li>
    <li><b><?php echo __('Signature Whitelist');?>:</b> <?php echo __('This list (can) contain a set of addresses that are allowed to be entered as attribute values but will be blocked from being exported to NIDS-es.');?><br /><br /> </li>
</ul>
</div>
