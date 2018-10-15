<div class="actions <?php echo $debugMode;?>">
    <ol class="nav nav-list">
            <li><?php echo $this->Html->link(__('Quick Start'), array('controller' => 'pages', 'action' => 'display', 'doc', 'quickstart')); ?></li>
            <li><?php echo $this->Html->link(__('General Layout'), array('controller' => 'pages', 'action' => 'display', 'doc', 'general')); ?></li>
            <li><?php echo $this->Html->link(__('General Concepts'), array('controller' => 'pages', 'action' => 'display', 'doc', 'concepts')); ?></li>
            <li><?php echo $this->Html->link(__('User Management and Global actions'), array('controller' => 'pages', 'action' => 'display', 'doc', 'user_management')); ?></li>
            <li><?php echo $this->Html->link(__('Using the system'), array('controller' => 'pages', 'action' => 'display', 'doc', 'using_the_system')); ?></li>
            <li class="active"><?php echo $this->Html->link(__('Administration'), array('controller' => 'pages', 'action' => 'display', 'doc', 'administration')); ?>
            <ul class="nav nav-list">
                <li><a href="#diagnostics"><?php echo __('Settings and Diagnostics');?></a></li>
                <li><a href="#blacklist"><?php echo __('Blacklist');?></a></li>
                <li><a href="#regexp"><?php echo __('Import Regexp');?></a></li>
                <li><a href="#whitelist"><?php echo __('Signature Whitelist');?></a></li>
                <li><a href="#user"><?php echo __('User Management');?></a></li>
                <li><a href="#roles"><?php echo __('Role Management');?></a></li>
                <li><a href="#logs"><?php echo __('Logging');?></a></li>
                <li><a href="#admin_tools"><?php echo __('Administrative Tools');?></a></li>
                <li><a href="#background"><?php echo __('Background Processing');?></a></li>
                <li><a href="#faq"><?php echo __('FAQ');?></a></li>
            </ul>
        </li>
        <li><?php echo $this->Html->link(__('Categories and Types'), array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
    </ol>
</div>

<div class="index">
    <h2><a id="diagnostics"></a><?php echo __('Server settings and diagnostics');?></h2>
    <p><?php echo __('Since version 2.3, MISP has a settings and diagnostics tool that allows site-admins to manage and diagnose their MISP installation. You can access this by navigating to Administration - Server settings');?>
    <p><img src="<?php echo $baseurl;?>/img/doc/settings_1.png" alt = "" title = "<?php echo __('Server settings overview with all of the tabs explained.');?>"/></p><br />
    <p><?php echo __('The settings and diagnostics tool is split up into several aspects, all accessible via the tabs on top of the tool. For any unset or incorrectly set setting, or failed diagnostic a number next to the tab name will indicate the number and severity of the issues. If the number is written with a red font, it means that the issue is critical. First, let\'s look at the various tabs');?>:</p>
    <ul>
        <li><b><?php echo __('Overview');?></b>: <?php echo __('General overview of the current state of your MISP installation');?></li>
        <li><b><?php echo __('MISP settings');?></b>: <?php echo __('Basic MISP settings. This includes the way MISP handles the default settings for distribution settings, whether background jobs are enabled, etc');?></li>
        <li><b><?php echo __('GnuPG settings');?></b>: <?php echo __('GnuPG related settings.');?></li>
        <li><b><?php echo __('Proxy settings');?></b>: <?php echo __('HTTP proxy related settings.');?></li>
        <li><b><?php echo __('Security settings');?></b>: <?php echo __('Settings controlling the brute-force protection and the application\'s salt key.');?></li>
        <li><b><?php echo __('Misc settings');?></b>: <?php echo __('You change the debug options here, but make sure that debug is always disabled on a production system.');?></li>
        <li><b><?php echo __('Diagnostics');?></b>: <?php echo __('The diagnostics tool checks if all directories that MISP uses to store data are writeable by the apache user. Also, the tool checks whether the STIX libraries and GnuPG are working as intended.');?></li>
        <li><b><?php echo __('Workers');?></b>: <?php echo __('Shows the background workers (if enabled) and shows a warning if they are not running. Admins can also restart the workers here.');?></li>
        <li><b><?php echo __('Download report');?></b>: <?php echo __('Download a report in JSON format, compiled of all of the settings visible in the tool.');?></li>
    </ul>
    <p><img src="<?php echo $baseurl;?>/img/doc/settings_2.png" alt = "" title = "<?php echo __('The settings tabs explained.');?>"/></p><br />
    <p><?php echo __('Each of the setting pages is a table with each row representing a setting. Coloured rows indicate that the setting is incorrect / not set and the colour determines the severity (red = critical, yellow = recommended, green = optional). The columns are as follows');?>:
    <ul>
        <li><b><?php echo __('Priority');?></b>: <?php echo __('The severity of the setting.');?></li>
        <li><b><?php echo __('Setting');?></b>: <?php echo __('The setting name.');?></li>
        <li><b><?php echo __('Value');?></b>: <?php echo __('The current value of the setting.');?></li>
        <li><b><?php echo __('Description');?></b>: <?php echo __('A description of what the setting does.');?></li>
        <li><b><?php echo __('Error Message');?></b>: <?php echo __('If the setting is incorrect / not set, then this field will let the user know what is wrong.');?></li>
    </ul>
    <p><img src="<?php echo $baseurl;?>/img/doc/settings_3.png" alt = "" title = "<?php echo __('The workers tab.');?>"/></p><br />
    <p><?php echo __('The workers tab shows a list of the workers that MISP can use. You can restart the workers using the restart all workers, If the button doesn\'t work, make sure that the workers were started using the apache user. This can however only be done using the command line, refer to the INSTALL.txt documentation on how to let the workers automatically start on each boot.');?></p>
    <ul>
        <li><b><?php echo __('Worker Type');?></b>: <?php echo __('The worker type is determined by the queue it monitors. MISP currently has 5 queues (cache, default, prio, email and a special _schdlr_ queue).');?></li>
        <li><b><?php echo __('Worker Id');?></b>: <?php echo __('The ID is made up of the machine name, the PID of the worker and the queue it monitors.');?></li>
        <li><b><?php echo __('Status');?></b>: <?php echo __('Displays OK if the worker is running. If the _schdlr_ worker is the only one not running make sure that you copy the config file into the cakeresque directory as described in the INSTALL.txt documentation.');?></li>
    </ul>
    <hr />
    <h2><a id="blacklist"></a><?php echo __('Import Blacklist');?></h2>
    <?php echo __('It is possible to ban certain values from ever being entered into the system via an event info field or an attribute value. This is done by blacklisting the value in this section.');?><br />
    <h3><?php echo __('Adding and modifying entries');?></h3>
    <?php echo __('Administrators can add, edit or delete blacklisted items by using the appropriate functions in the list\'s action menu and the menu on the left.');?><br />
    <hr />
    <h2><a id="regexp"></a><?php echo __('Import Regexp');?></h2>
    <?php echo __('The system allows administrators to set up rules for regular expressions that will automatically alter newly entered or imported events.');?><br />
    <h3><?php echo __('The purpose of Import Regexp entries');?></h3>
    <?php echo __('They can be used for several things, such as unifying the capitalisation of file paths for more accurate event correlation or to automatically censor the usernames and use system path variable names (changing C:\Users\UserName\Appdata\Roaming\file.exe to %APPDATA%\file.exe).<br />
        The second use is blocking, if a regular expression is entered with a blank replacement, any event info or attribute value containing the expression will not be added. Please make sure the entered regexp expression follows the preg_replace pattern rules as described <a href="http://php.net/manual/en/function.preg-replace.php">here</a>.');?><br />
    <h3><?php echo __('Adding and modifying entries');?></h3>
    <?php echo __('Administrators can add, edit or delete regular expression rules, which are made up of a regex pattern that the system searches for and a replacement for the detected pattern.');?><br />
    <p><img src="<?php echo $baseurl;?>/img/doc/regexp.png" alt = "" title = "<?php echo __('Add, edit or remove Regexp entries that will affect all newly created attributes here.');?>"/></p><br />
    <hr />
    <h2><a id="whitelist"></a><?php echo __('Managing the Signature whitelist');?></h2>
    <?php echo __('The signature whitelist view, accessible through the administration menu on the left, allows administrators to create and maintain a list of addresses that are whitelisted from ever being added to the NIDS signatures. Addresses listed here will be commented out when exporting the NIDS list.');?><br />
    <h3><?php echo __('Whitelisting an address');?>:</h3>
        <?php echo __('While in the whitelist view, click on New Whitelist on the left to bring up the add whitelist view to add a new address.');?> <br />
    <h3><?php echo __('Managing the list');?>:</h3>
        <?php echo __('When viewing the list of whitelisted addresses, the following pieces of information are shown: The ID of the whitelist entry (assigned automatically when a new address is added), the address itself that is being whitelisted and a set of controls allowing you to delete the entry or edit the address.');?><br />
    <img src="<?php echo $baseurl;?>/img/doc/whitelist.png" alt = "Whitelist" title = "<?php echo __('You can edit or delete currently white-listed addresses using the action buttons on this list.');?>"/><br />
    <hr />
    <h2><a id="user"></a><?php echo __('Managing the users');?>:</h2>
    <?php echo __('As an admin, you can set up new accounts for users, edit the profiles of users, delete them, or just have a look at all the viewers\' profiles. Organisation admins are restricted to executing the same actions on their organisation\'s users only.');?><br />
    <h3><?php echo __('Adding a new user');?>:</h3>
    <?php echo __('To add a new user, click on the New User button in the administration menu to the left and fill out the following fields in the view that is loaded');?>:<br />
    <img src="<?php echo $baseurl;?>/img/doc/add_user.png" alt = "<?php echo __('Add user');?>" title = "<?php echo __('Fill this form out to add a new user. Keep in mind that the drop-down menu titled Role controls the privileges the user will have.');?>"/>
    <ul>
        <li><b><?php echo __('Email');?>:</b> <?php echo __('The user\'s e-mail address, this will be used as his/her login name and as an address to send all the automatic e-mails and e-mails sent by contacting the user as the reporter of an event.');?><br /></li>
        <li><b><?php echo __('Password');?>:</b> <?php echo __('A temporary password for the user that he/she should change after the first login. Make sure that it is at least 6 characters long, includes a digit or a special character and contains at least one upper-case and at least one lower-case character.');?><br /></li>
        <li><b><?php echo __('Confirm Password');?>:</b> <?php echo __('This should be an exact copy of the Password field.');?><br /></li>
        <li><b><?php echo __('Org');?>:</b><?php echo __('The organisation of the user. Entering ADMIN into this field will give administrator privileges to the user. If you are an organisation admin, then this field will be unchangeable and be set to your own organisation.');?><br /></li>
        <li><b><?php echo __('Roles');?>:</b> <?php echo __('A drop-down list allows you to choose a role-group that the user should belong to. Roles define the privileges of the user. To learn more about roles, <a href=#roles>click here</a>.');?><br /></li>
        <li><b><?php echo __('Receive alerts when events are published');?>:</b> <?php echo __('This option will subscribe the new user to automatically generated e-mails whenever an event is published.');?><br /></li>
        <li><b><?php echo __('Receive alerts from "contact reporter" requests');?>:</b> <?php echo __('This option will subscribe the new user to e-mails that are generated when another user tries to get in touch with an event\'s reporting organisation that matches that of the new user.');?><br /></li>
        <li><b><?php echo __('Authkey');?>:</b> <?php echo __('This is assigned automatically and is the unique authentication key of the user (he/she will be able to reset this and receive a new key). It is used for exports and for connecting one server to another, but it requires the user to be assigned to a role that has auth permission enabled.');?><br /></li>
        <li><b><?php echo __('NIDS Sid');?>:</b> <?php echo __('Nids ID, not yet implemented.');?><br /></li>
        <li><b><?php echo __('GnuPGkey');?>:</b> <?php echo __('The key used for encrypting e-mails sent through the system.');?> <br /></li>
    </ul>
    <h3><?php echo __('Listing all users');?>:</h3>
    <?php echo __('To list all current users of the system, just click on List Users under the administration menu to the left. A view will be loaded with a list of all users and the following columns of information');?>:<br />
    <img src="<?php echo $baseurl;?>/img/doc/list_users.png" alt = "<?php echo __('List users');?>" title = "<?php echo __('View, Edit or Delete a user using the action buttons to the right.');?>"/><br />
    <ul>
        <li><b>Id:</b> <?php echo __('The user\'s automatically assigned ID number.');?><br /></li>
        <li><b>Org:</b> <?php echo __('The organisation that the user belongs to.');?><br /></li>
        <li><b><?php echo __('Email');?>:</b> <?php echo __('The e-mail address (and login name) of the user.');?><br /></li>
        <li><b><?php echo __('Autoalert');?>:</b> <?php echo __('Shows whether the user has subscribed to auto-alerts and is always receiving the mass-emails regarding newly published events that he/she is eligible for.');?><br /></li>
        <li><b>Contactalert:</b> <?php echo __('Shows whether the user has the subscription to contact reporter e-mails directed at his/her organisation turned on or off.');?><br /></li>
        <li><b>GnuPGkey:</b> <?php echo __('Shows whether the user has entered a GnuPGkey yet.');?><br /></li>
        <li><b>Nids Sid:</b> <?php echo __('Shows the currently assigned NIDS ID.');?><br /></li>
        <li><b><?php echo __('Termsaccepted');?>:</b> <?php echo __('This flag indicates whether the user has accepted the terms of use or not.');?><br /></li>
        <li><b><?php echo __('Newsread');?>:</b> <?php echo __('The last point in time when the user has looked at the news section of the system.');?><br /></li>
        <li><b><?php echo __('Action Buttons');?>:</b> <?php echo __('Here you can view a detailed view of a user, edit the basic details of a user (same view as the one used for creating a new user, but all the fields come filled out by default) or remove a user completely.');?> <br /></li>
    </ul>
    <h3><?php echo __('Editing a user');?>:</h3>
    <?php echo __('To add a new user, click on the New User button in the administration menu to the left and fill out the following fields in the view that is loaded');?>:<br />
    <ul>
        <li><b><?php echo __('Email');?>:</b> <?php echo __('The user\'s e-mail address, this will be used as his/her login name and as an address to send all the automatic e-mails and e-mails sent by contacting the user as the reporter of an event.');?><br /></li>
        <li><b><?php echo __('Password');?>:</b> <?php echo __('It is possible to assign a new password manually for a user. For example, in case that he/she forgot the old one a new temporary one can be assigned. Make sure to check the "Change password" field if you do give out a temporary password, so that the user will be forced to change it after login.');?><br /></li>
        <li><b><?php echo __('Confirm Password');?>:</b> <?php echo __('This should be an exact copy of the Password field.');?><br /></li>
        <li><b><?php echo __('Org');?>:</b><?php echo __('The organisation of the user. Entering ADMIN into this field will give administrator privileges to the user. If you are an organisation admin, then this field will be unchangeable and be set to your own organisation.');?><br /></li>
        <li><b><?php echo __('Roles');?>:</b> <?php echo __('A drop-down list allows you to choose a role-group that the user should belong to. Roles define the privileges of the user. To learn more about roles, <a href=#roles>click here</a>.');?><br /></li>
        <li><b><?php echo __('Receive alerts when events are published');?>:</b> <?php echo __('This option will subscribe the user to automatically generated e-mails whenever an event is published.');?><br /></li>
        <li><b><?php echo __('Receive alerts from "contact reporter" requests');?>:</b> <?php echo __('This option will subscribe the user to e-mails that are generated when another user tries to get in touch with an event\'s reporting organisation that matches that of the user.');?><br /></li>
        <li><b><?php echo __('Authkey');?>:</b> <?php echo __('It is possible to request a new authentication key for the user.');?> <br /></li>
        <li><b><?php echo __('NIDS Sid');?>:</b> <?php echo __('Nids ID, not yet implemented.');?><br /></li>
        <li><b><?php echo __('Termsaccepted');?>:</b> <?php echo __('Indicates whether the user has accepted the terms of use already or not.');?><br /></li>
        <li><b><?php echo __('Change Password');?>:</b> <?php echo __('Setting this flag will require the user to change password after the next login.');?><br /></li>
        <li><b><?php echo __('GnuPGkey');?>:</b> <?php echo __('The key used for encrypting e-mails sent through the system.');?> <br /></li>
    </ul>
    <h3><?php echo __('Contacting a user');?>:</h3>
    <?php echo __('Site admins can use the "Contact users" feature to send all or an individual user an e-mail. Users that have a GnuPG key set will receive their e-mails encrypted. When clicking this button on the left, you\'ll be presented with a form that allows you to specify the type of the e-mail, who it should reach and what the content is using the following options');?>:<br />
    <img src="<?php echo $baseurl;?>/img/doc/contact.png" alt = "<?php echo __('Contact');?>" title = "<?php echo __('Contact your users here.');?>"/><br />
    <ul>
        <li><b><?php echo __('Action');?>:</b> <?php echo __('This defines the type of the e-mail, which can be a custom message or a password reset. Password resets automatically include a new temporary password at the bottom of the message and will automatically change the user\'s password accordingly.');?><br /></li>
        <li><b><?php echo __('Recipient');?>:</b> <?php echo __('The recipient toggle lets you contact all your users, a single user (which creates a second drop-down list with all the e-mail addresses of the users) and potential future users (which opens up a text field for the e-mail address and a text area field for a GnuPG public key).');?><br /></li>
        <li><b><?php echo __('Subject');?>:</b> <?php echo __('In the case of a custom e-mail, you can enter a subject line here.');?><br /></li>
        <li><b><?php echo __('Subject');?>:</b> <?php echo __('In the case of a custom e-mail, you can enter a subject line here.');?><br /></li>
        <li><b><?php echo __('Custom message checkbox');?>:</b> <?php echo __('This is available for password resets, you can either write your own message (which will be appended with a temporary key and the signature), or let the system generate one automatically.');?><br /></li>
    </ul>
    <?php echo __('Keep in mind that all e-mails sent through this system will, in addition to your own message, will be signed in the name of the instance\'s host organisation\'s support team, will include the e-mail address of the instance\'s support (if the contact field is set in the bootstrap file), and will include the instance\'s GnuPG signature for users that have a GnuPG key set (and thus are eligible for an encrypted e-mail).');?>
    <hr />
    <h2><a id="roles"></a><?php echo __('Managing the roles');?></h2>
    <?php echo __('Privileges are assigned to users by assigning them to rule groups, which use one of four options determining what they can do with events and four additional privilege elevating settings. The four options for event manipulation are: Read Only, Manage My Own Events, Manage Organisation Events, Manage &amp; Publish Organisation Events. The extra privileges are admin, sync, authentication key usage and audit permission');?><br />
    <ul>
        <li><b><?php echo __('Read Only');?>:</b> <?php echo __('This allows the user to browse events that his organisation has access to, but doesn\'t allow any changes to be made to the database.');?></li>
        <li><b><?php echo __('Manage My Own Events');?>:</b> <?php echo __('The second option, gives its users rights to create, modify or delete their own events, but they cannot publish them.');?></li>
        <li><b><?php echo __('Manage Organization Events');?>:</b> <?php echo __('Allows users to create events or modify and delete events created by a member of their organisation.');?></li>
        <li><b><?php echo __('Manage &amp; Publish Organisation Events');?>:</b> <?php echo __('This last setting, gives users the right to do all of the above and also to publish the events of their organisation.');?></li>
        <li><b><?php echo __('Perm sync');?>:</b> <?php echo __('This setting allows the users of the role to be used as a synchronisation user. The authentication key of this user can be handed out to the administrator of a remote MISP instance to allow the synchronisation features to work.');?></li>
        <li><b><?php echo __('Perm auth');?>:</b> <?php echo __('This setting enables the authentication key of the role\'s users to be used for rest requests.');?> </li>
        <li><b><?php echo __('Perm admin');?>:</b> <?php echo __('Gives the user limited administrator privileges, this setting is used for the organisation admins');?>. </li>
        <li><b><?php echo __('Perm site admin');?>:</b> <?php echo __('Gives the user full administrator privileges, this setting is used for the site admins.');?> </li>
        <li><b><?php echo __('Perm audit');?>:</b> <?php echo __('Grants access to the logs. With the exception of site admins, only logs generated by the user\'s own org are visible.');?> </li>
        <li><b><?php echo __('Perm regexp access');?>:</b> <?php echo __('Allows the users with this permission enabled to edit the regular expression table. Be careful when giving out this permission, incorrect regular expressions can be very harmful (infinite loops, loss of data, etc.).');?></li>
        <li><b><?php echo __('Perm tagger');?>:</b> <?php echo __('Allows the user with this permission to create custom tags and assign them to events.');?> </li>
    </ul>
    <h3><?php echo __('Creating roles');?>:</h3>
    <?php echo __('When creating a new role, you will have to enter a name for the role to be created and set up the permissions (as described above) using the radio toggle and the four check-boxes.');?><br />
    <h3><?php echo __('Listing roles');?>:</h3>
    <?php echo __('By clicking on the List Roles button, you can view a list of all the currently registered roles and a list of the permission flags turned on for each. In addition, you can find buttons that allow you to edit and delete the roles. Keep in mind that you will need to first remove every member from a role before you can delete it.');?><br />
    <img src="<?php echo $baseurl;?>/img/doc/list_groups.png" alt = "<?php echo __('List roles');?>" title = "<?php echo __('You can View, Edit or Delete roles using the action buttons to the right in each row. Keep in mind that a role has to be devoid of members before it can be deleted.');?>"/><br />
    <hr />
    <h2><a id="logs"></a><?php echo __('Using the logs of MISP');?></h2>
    <?php echo __('Users with audit permissions are able to browse or search the logs that MISP automatically appends each time certain actions are taken (actions that modify data or if a user logs in and out).');?><br />
    <?php echo __('Generally, the following actions are logged');?>:<br /><br />
    <ul>
        <li><b><?php echo __('User');?>:</b> <?php echo __('Creation, deletion, modification, Login / Logout');?><br /></li>
        <li><b><?php echo __('Event');?>:</b><?php echo __('Creation, deletion, modification, publishing');?><br /></li>
        <li><b><?php echo __('Attribute');?>:</b> <?php echo __('Creation, deletion, modification');?><br /></li>
        <li><b><?php echo __('ShadowAttribute');?>:</b> <?php echo __('Creation, deletion, Accept, Discard');?><br /></li>
        <li><b><?php echo __('Roles');?>:</b> <?php echo __('Creation, deletion, modification');?><br /></li>
        <li><b><?php echo __('Blacklist');?>:</b> <?php echo __('Creation, deletion, modification');?><br /></li>
        <li><b><?php echo __('Whitelist');?>:</b> <?php echo __('Creation, deletion, modification');?><br /></li>
        <li><b><?php echo __('Regexp');?>:</b> <?php echo __('Creation, deletion, modification');?></li>
    </ul>
    <br />
    <h3><?php echo __('Browsing the logs');?>:</h3>
    <?php echo __('Listing all the log entries will show the following columns generated by the users of your organisation (or all organisations in the case of site admins)');?>:<br />
    <img src="<?php echo $baseurl;?>/img/doc/list_logs.png" alt = "<?php echo __('List logs');?>" title = "<?php echo __('Here you can view a list of all logged actions.');?>"/><br /><br />
    <ul>
        <li><b><?php echo __('Id');?>:</b> <?php echo __('The automatically assigned ID number of the entry.');?><br /></li>
        <li><b><?php echo __('Email');?>:</b> <?php echo __('The e-mail address of the user whose actions triggered the entry.');?><br /></li>
        <li><b><?php echo __('Org');?>:</b> <?php echo __('The organisation of the above mentioned user.');?><br /></li>
        <li><b><?php echo __('Created');?>:</b> <?php echo __('The date and time when the entry originated.');?><br /></li>
        <li><b><?php echo __('Action');?>:</b> <?php echo __('The action\'s type. This can include: login/logout for users, add, edit, delete for events, attributes, users and servers.');?><br /></li>
        <li><b><?php echo __('Title');?>:</b> <?php echo __('The title of an event always includes the target type (Event, User, Attribute, Server), the target\'s ID and the target\'s name (for example: e-mail address for users, event description for events).');?><br /></li>
        <li><b><?php echo __('Change');?>:</b> <?php echo __('This field is only filled out for entries with the action being add or edit. The changes are detailed in the following format');?>:<br />
                <i>variable (initial_value)</i> =&gt; <i>(new_value)</i>,...<br />
                <?php echo __('When the entry is about the creation of a new item (such as adding a new event) then the change will look like this for example');?>:<br />
                <i>org()</i> =&gt; <i>(ADMIN)</i>, <i>date()</i> =&gt; <i>(20012-10-19)</i>,... <br />
    </ul>
    <img src="<?php echo $baseurl;?>/img/doc/search_log.png" alt = "<?php echo __('Search log');?>" style="float:right;" title = "<?php echo __('You can search the logs using this form, narrow down your search by filling out several fields.');?>"/>
    <h3><?php echo __('Searching the Logs');?>:</h3>
    <?php echo __('Another way to browse the logs is to search it by filtering the results according to the following fields (the search is a sub-string search, the sub-string has to be an exact match for the entry in the field that is being searched for)');?>:<br /><br />
    <ul>
        <li><b><?php echo __('Email');?>:</b> <?php echo __('By searching by Email, it is possible to view the log entries of a single user.');?><br /></li>
        <li><b><?php echo __('Org');?>:</b> <?php echo __('Searching for an organisation allows you to see all actions taken by any member of the organisation.');?><br /></li>
        <li><b><?php echo __('Action');?>:</b> <?php echo __('With the help of this drop down menu, you can search for various types of actions taken (such as logins, deletions, etc).');?><br /></li>
        <li><b><?php echo __('Title');?>:</b> <?php echo __('There are several ways in which to use this field, since the title fields contain several bits of information and the search searches for any substrings contained within the field, it is possible to just search for the ID number of a logged event, the username / server\'s name / event\'s name / attribute\'s name of the event target.');?><br /></li>
        <li><b><?php echo __('Change');?>:</b> <?php echo __('With the help of this field, you can search for various specific changes or changes to certain variables (such as published will find all the log entries where an event has gotten published, ip-src will find all attributes where a source IP address has been entered / edited, etc).');?><br /></li>
    </ul>
    <hr />
    <h2><a id="admin_tools"></a><?php echo __('Administrative Tools');?></h2>
    <?php echo __('MISP has a couple of administrative tools that help administrators keep their instance up to date and healthy. The list of these small tools can change rapidly with each new version, but they should be self-explanatory. Make sure to check this section after upgrading to a new version, just in case there is a new upgrade script in there - though if this is the case it will be mentioned in the upgrade instructions.');?><br /><br />
    <hr />
    <h2><a id="background"></a><?php echo __('Background Processing');?></h2>
    <?php echo __('If enabled, MISP can delegate a lot of the time intensive tasks to the background workers. These will then be executed in order, allowing the users of the instance to keep using the system without a hiccup and without having to wait for the process to finish. It also allows for certain tasks to be scheduled and automated.');?>
    <h3><?php echo __('Command Line Tools for the Background Workers');?></h3>
    <?php echo __('The background workers are powered by <a href="https://github.com/kamisama/Cake-Resque">CakeResque</a>, so all of the CakeResque commands work.
        To start all of the workers needed by MISP go to your <code>/var/www/MISP/app/Console/worker</code> (assuming a standard installation path) and execute start.sh.
        To interact with the workers, here is a list of useful commands. Go to your <code>/var/www/MISP/app/Console</code> (assuming a standard installation path) and execute one of the following commands as a parameter to <code>./cake CakeResque.CakeResque</code> (for example: <code>./cake CakeResque.CakeResque tail</code>)');?>:<br /><br />
    <ul>
        <li><b><?php echo __('tail');?></b>: <?php echo __('tail the various log files that CakeResque creates, just choose the one from the list that you are interested in.');?></li>
        <li><b><?php echo __('cleanup');?></b>: <?php echo __('terminate the job that a worker is working on immediately. You will be presented with a choice of workers to choose from when executing this command.');?></li>
        <li><b><?php echo __('clear');?></b>: <?php echo __('Clear the queue of a worker immediately.');?></li>
        <li><b><?php echo __('stats');?></b>: <?php echo __('shows some statistics about your workers including the count of successful and failed jobs.');?></li>
    </ul>
    <?php echo __('The other commands should not be needed, instead of starting / stopping or restarting workers use the supplied start.sh (it stops all workers and starts them all up again). For further instructions on how to use the console commands for the workers, visit the <a href="http://cakeresque.kamisama.me/commands#cleanup">CakeResque list of commands</a>.');?><br />
    <h3><?php echo __('Monitoring the Background Processes');?></h3>
    <?php echo __('The "Jobs" menu item within the Administration menu allows site admins to get an overview of all of the currently and in the past scheduled jobs. Admins can see the status of each job, and what the queued job is trying to do. If a job fails, it will try to set an error message here too. The following columns are shown in the jobs table');?>:<br /><br />
    <ul>
        <li><b><?php echo __('Id');?></b>: <?php echo __('The job\'s ID (this is the ID of the job\'s meta-data stored in the default data-store, not to be confused with the process ID stored in the redis database and used by the workers.)');?></li>
        <li><b><?php echo __('Process');?></b>: <?php echo __('The process\'s ID.');?></li>
        <li><b><?php echo __('Worker');?></b>: <?php echo __('The name of the worker queue. There are 3+1 workers running if background jobs are enabled: default, cache, email, and a special Scheduler (this should never show up in the jobs table).');?></li>
        <li><b><?php echo __('Job Type');?></b>: <?php echo __('The name of the queued job.');?></li>
        <li><b><?php echo __('Input');?></b>: <?php echo __('Shows a basic input handled by the job - such as "Event:50" for a publish email alert job for event 50.');?></li>
        <li><b><?php echo __('Message');?></b>: <?php echo __('This will show what the job is currently doing or alternatively an error message describing why a job failed.');?></li>
        <li><b><?php echo __('Org');?></b>: <?php echo __('The string identifier of the organisation that has scheduled the job.');?></li>
        <li><b><?php echo __('Status');?></b>: <?php echo __('The status reported by the worker.');?></li>
        <li><b><?php echo __('Retries');?></b>: <?php echo __('Currently unused, it is planned to introduced automatic delayed retries for the background processing to add resilience.');?></li>
        <li><b><?php echo __('Progress');?></b>: <?php echo __('A progress bar showing how the job is coming along.');?></li>
    </ul>
    <br /><img src="<?php echo $baseurl;?>/img/doc/jobs.png" alt = "" title = "Site administrators can monitor the process of all queued jobs here."/><br />
    <h3><?php echo __('Scheduling Jobs and Recurring Jobs');?></h3>
    <?php echo __('Apart from off-loading long-lasting jobs to the background workers, there is a second major benefit of enabling the background workers: Site-administrators can schedule recurring tasks for the jobs that generally take the longest to execute. At the moment this includes pushing / pulling other instances and generating a full export cache for every organisation and export type. MISP comes with these 3 tasks pre-defined, but further tasks are planned. The following fields make up the scheduled tasks table');?>: <br /><br />
    <ul>
        <li><b><?php echo __('Id');?></b>: <?php echo __('The ID of the task.');?></li>
        <li><b><?php echo __('Type');?></b>: <?php echo __('The type of the task.');?></li>
        <li><b><?php echo __('Frequency');?> (h)</b>: <?php echo __('This number sets how often the job should be executed in hours. Setting this to 168 and picking the next execution on Sunday at 01:00 would execute the task every Sunday at 1 AM. Setting this value to 0 will make the task only run once on the scheduled date / time without rescheduling it afterwards.');?></li>
        <li><b><?php echo __('Scheduled Time');?></b>: <?php echo __('The time (in 24h format) when the task should be executed the next time it runs (and all consecutive times if a multiple of 24 is chosen for frequency).');?></li>
        <li><b><?php echo __('Next Run');?></b>: <?php echo __('The date on which the task should be executed.');?></li>
        <li><b><?php echo __('Description');?></b>: <?php echo __('A brief description of the task.');?></li>
        <li><b><?php echo __('Message');?></b>: <?php echo __('This field shows when the job was queued by the scheduler for execution.');?></li>
    </ul>
    <br /><img src="<?php echo $baseurl;?>/img/doc/schedule.png" alt = "" title = "<?php echo __('Site administrators can schedule reccuring tasks on this page.');?>"/><br />
    <h2 ><a id="faq"></a><?php echo __('Frequently asked questions');?></h2>
    <b><?php echo __('Losing access to the platform and resetting the password');?></b><br /><br />
    <?php echo __('If you ever lock yourself out of MISP as a site admin, there is a command line tool to reset your password. This can also be handy if you have changed the salt key and invalidated all of the passwords.');?><br />
    <?php echo __('Simply run the command');?>:<br />
    <code>/var/www/MISP/app/Console/cake Password my.email@address.com <?php echo __('my_new_password');?></code><br />
    <?php echo __('This will create a new password hash using the currently set salt.');?>
</div>
