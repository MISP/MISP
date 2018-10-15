<div class="actions <?php echo $debugMode;?>">
    <ol class="nav nav-list">
        <li><?php echo $this->Html->link(__('Quick Start'), array('controller' => 'pages', 'action' => 'display', 'doc', 'quickstart')); ?></li>
        <li class="active"><?php echo $this->Html->link(__('General Layout'), array('controller' => 'pages', 'action' => 'display', 'doc', 'general')); ?></li>
        <li><?php echo $this->Html->link(__('General Concepts'), array('controller' => 'pages', 'action' => 'display', 'doc', 'concepts')); ?></li>
        <li><?php echo $this->Html->link(__('User Management and Global actions'), array('controller' => 'pages', 'action' => 'display', 'doc', 'user_management')); ?></li>
        <li><?php echo $this->Html->link(__('Using the system'), array('controller' => 'pages', 'action' => 'display', 'doc', 'using_the_system')); ?></li>
        <li><?php echo $this->Html->link(__('Administration'), array('controller' => 'pages', 'action' => 'display', 'doc', 'administration')); ?></li>
        <li><?php echo $this->Html->link(__('Categories and Types'), array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
    </ol>
</div>

<div class="index">
<h2><?php echo __('General Layout');?></h2>
<h3><?php echo __('The top bar');?></h3>
    <p><img src="<?php echo $baseurl;?>/img/doc/menu_image.png" alt = "" title = "<?php echo __('This is the main menu that will be accessible from all of the views. In some instances, some additional buttons that will appear on top of these when a view provides it.');?>"/></p>
    <p><?php echo __('This menu contains all of the main functions of the site as a series of dropdown menus. These contains all (from the current user\'s perspective) accessible functions sorted into several groups.');?></p>
    <ul>
        <li><b><?php echo __('Home button');?>:</b> <?php echo __('This button will return you to the start screen of the application, which is the event index page (more about this later).');?></li>
        <li><b><?php echo __('Event Actions');?>:</b> <?php echo __('All the malware data entered into MISP is made up of an event object that is described by its connected attributes. The Event actions menu gives access to all the functionality that has to do with the creation, modification, deletion, publishing, searching and listing of events and attributes.');?></li>
        <li><b><?php echo __('Input Filters');?>:</b> <?php echo __('Input filters alter what and how data can be entered into this instance. Apart from the basic validation of attribute entry by type, it is possible for the site administrators to define regular expression replacements and blacklists for certain values in addition to blocking certain values from being exportable. Users can view these replacement and blacklist rules here whilst administrator can alter them.');?></li>
        <li><b><?php echo __('Global Actions');?>:</b> <?php echo __('This menu gives you access to information about MISP and this instance. You can view and edit your own profile, view the manual, read the news or the terms of use again, see a list of the active organisations on this instance and a histogram of their contributions by attribute type.');?></li>
        <li><b><?php echo __('Sync Actions');?>:</b> <?php echo __('With administrator access rights, shows a list of the connected instances and allows the initiation of a push and a pull (more about the synchronisation mechanisms later).');?></li>
        <li><b><?php echo __('Administration');?>:</b> <?php echo __('Administrators can add, edit or remove user accounts and user roles. Roles define the access rights to certain features such as publishing of events, usage of the REST interface or synchronisation of any user belonging to the given role. Site administrators can also access a contact form, through which it is possible to reset the passwords of users, or to just get in touch with them via encrypted e-mails.');?></li>
        <li><b><?php echo __('Audit');?>:</b> <?php echo __('If you have audit permissions, you can view the logs for your organisation (or for site admins for the entire system) here or even search the logs if you are interested in something specific.');?></li>
        <li><b><?php echo __('Discussions');?>:</b> <?php echo __('Link to the discussion threads.');?></li>
        <li><b><?php echo __('Proposal Notifications');?>: </b> <?php echo __('This shows how many proposals your organisation has received and across how many events they are spread out. Clicking this will take you to the list of proposals.');?></li>
        <li><b><?php echo __('Log out');?>:</b> <?php echo __('Logs you out of the system.');?></li>
    </ul>

<h3><?php echo __('A list of the contents of each of the above drop-down menus');?></h3>
    <h5><?php echo __('Event actions');?></h5>
    <ul>
        <li><b><?php echo __('List Events');?>:</b> <?php echo __('Lists all the events in the system that are not private or belong to your organisation. You can add, modify, delete, publish or view individual events from this view.');?></li>
        <li><b><?php echo __('Add Event');?>:</b> <?php echo __('Allows you to fill out an event creation form and create the event object, which you can start populating with attributes.');?></li>
        <li><b><?php echo __('List Attributes');?>:</b> <?php echo __('Lists all the attributes in the system that are not private or belong to your organisation. You can modify, delete or view each individual attribute from this view.');?></li>
        <li><b><?php echo __('Search Attributes');?>:</b> <?php echo __('You can set search terms for a filtered attribute index view here.');?></li>
        <li><b><?php echo __('View Proposals');?>:</b> <?php echo __('Shows a list of all proposals that you are eligible to see.');?></li>
        <li><b><?php echo __('Events with proposals');?>: </b> <?php echo __('Shows all of the events created by your organsiation that has pending proposals.');?></li>
        <li><b><?php echo __('List Tags');?>:</b> <?php echo __('List all the tags that have been created by users with tag creation rights on this instance.');?></li>
        <li><b><?php echo __('Add Tag');?>:</b> <?php echo __('Create a new tag.');?></li>
        <li><b><?php echo __('List Templates');?>:</b> <?php echo __('List all of the templates created by users with template creation rights on this instance.');?></li>
        <li><b><?php echo __('Add Template');?>:</b> <?php echo __('Create a new template.');?></li>
        <li><b><?php echo __('Export');?>:</b> <?php echo __('Export the data accessible to you in various formats.');?></li>
        <li><b><?php echo __('Automation');?>:</b> <?php echo __('If you have authentication key access, you can view how to use your key to use the REST interface for automation here.');?></li>
    </ul>

    <h5><?php echo __('Input filters');?></h5>
    <ul>
        <li><b><?php echo __('Import Regexp');?>:</b> <?php echo __('You can view the Regular Expression rules, which modify the data that can be entered into the system. This can and should be used to help filter out personal information from automatic imports (such as removing the username from windows file paths), having unified representation for certain common values for easier correlation or simply standardising certain input. It is also possible to block certain values from being inserted. As a site administrator or a user with regex permission, you can also edit these rules.');?></li>
        <li><b><?php echo __('Signature Whitelist');?>:</b> <?php echo __('You can view the whitelist rules, which contain the values that are blocked from being used for exports and automation on this instance. Site administrators have access to editing this list.');?></li>
    </ul>

    <h5><?php echo __('Global Actions');?></h5>
    <ul>
        <li><b><?php echo __('News');?>:</b> <?php echo __('Read about the latest news regarding the MISP system.');?></li>
        <li><b><?php echo __('My Profile');?>:</b> <?php echo __('Manage your user account.');?></li>
        <li><b><?php echo __('Attribute Histogram');?>:</b> <?php echo __('View some statistics about the currently stored attributes.');?></li>
        <li><b><?php echo __('Role Permissions');?>:</b> <?php echo __('You can view the role permissions here.');?></li>
        <li><b><?php echo __('User Guide');?>:</b> <?php echo __('A link to this user guide.');?></li>
        <li><b><?php echo __('Terms &amp; Conditions');?>:</b> <?php echo __('View the terms &amp; conditions again.');?></li>
        <li><b><?php echo __('Statistics');?>: </b> <?php echo __('View a series of statistics about the users and the data on this instance.');?></li>
        <li><b><?php echo __('Log out');?>:</b> <?php echo __('Logs the current user out.');?></li>
    </ul>

    <h5><?php echo __('Sync Actions');?></h5>
    <ul>
        <li><b><?php echo __('List Servers');?>:</b> <?php echo __('Connect your MISP instance to other instances, or view and modify the currently established connections.');?></li>
    </ul>

    <h5><?php echo __('Administration');?></h5>
    <ul>
        <li><b><?php echo __('New User');?>:</b> <?php echo __('Create an account for a new user for your organisation. Site administrators can create users for any organisation.');?></li>
        <li><b><?php echo __('List Users');?>:</b> <?php echo __('View, modify or delete the currently registered users.');?></li>
        <li><b><?php echo __('New Role');?>:</b> <?php echo __('Create a new role group for the users of this instance, controlling their privileges to create, modify, delete and to publish events and to access certain features such as the logs or automation.');?></li>
        <li><b><?php echo __('List Roles');?>:</b> <?php echo __('List, modify or delete currently existing roles.');?></li>
        <li><b><?php echo __('Contact Users');?>:</b> <?php echo __('You can use this view to send messages to your current or future users or send them a new temporary password.');?></li>
        <li><b><?php echo __('Administrative Tools');?>:</b> <?php echo __('Various tools, upgrade scripts that can help a site-admin run the instance.');?></li>
        <li><b><?php echo __('Server Settings');?>:</b> <?php echo __('Set up and diagnose your MISP installation.');?></li>
        <li><b><?php echo __('Jobs');?>:</b> <?php echo __('View the background jobs and their progress.');?></li>
        <li><b><?php echo __('Scheduled Tasks');?>:</b> <?php echo __('Schedule the pre-defined tasks for your instance (this currently includes export caching, server pull and server push).');?></li>
    </ul>

    <h5><?php echo __('Audit');?></h5>
    <ul>
        <li><b><?php echo __('List Logs');?>:</b> <?php echo __('View the logs of the instance.');?></li>
        <li><b><?php echo __('Search Logs');?>:</b> <?php echo __('Search the logs by various attributes.');?></li>
    </ul>

        <h5><?php echo __('Discussions');?></h5>
    <ul>
        <li><b><?php echo __('List Discussions');?>:</b> <?php echo __('List all of the discussion threads.');?></li>
        <li><b><?php echo __('Start Discussion');?>:</b> <?php echo __('Create a new discussion thread.');?></li>
    </ul>
<h3><?php echo __('The left bar');?></h3>
    <p><?php echo __('This bar changes based on each page-group. The blue selection shows you what page you are on.');?></p>
</div>
