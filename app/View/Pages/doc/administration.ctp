<div class="actions <?php echo $debugMode;?>">
	<ol class="nav nav-list">
			<li><?php echo $this->Html->link('Quick Start', array('controller' => 'pages', 'action' => 'display', 'doc', 'quickstart')); ?></li>
			<li><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'doc', 'general')); ?></li>
			<li><?php echo $this->Html->link('General Concepts', array('controller' => 'pages', 'action' => 'display', 'doc', 'concepts')); ?></li>
			<li><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'doc', 'user_management')); ?></li>
			<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'doc', 'using_the_system')); ?></li>
			<li class="active"><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'doc', 'administration')); ?>
			<ul class="nav nav-list">
				<li><a href="#blacklist">Blacklist</a></li>
				<li><a href="#regexp">Import Regexp</a></li>
				<li><a href="#whitelist">Signature Whitelist</a></li>
				<li><a href="#user">User Management</a></li>
				<li><a href="#roles">Role Management</a></li>
				<li><a href="#logs">Logging</a></li>
				<li><a href="#admin_tools">Administrative Tools</a></li>
				<li><a href="#background">Background Processing</a></li>
			</ul>
		</li>
		<li><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'doc', 'categories_and_types')); ?></li>
	</ol>
</div>

<div class="index">
<h2><a id="blacklist"></a>Import Blacklist</h2>
It is possible to ban certain values from ever being entered into the system via an event info field or an attribute value. This is done by blacklisting the value in this section.<br />
<h3>Adding and modifying entries</h3>
Administrators can add, edit or delete blacklisted items by using the appropriate functions in the list's action menu and the menu on the left.<br />
<hr />
<h2><a id="regexp"></a>Import Regexp</h2>
The system allows administrators to set up rules for regular expressions that will automatically alter newly entered or imported events (from GFI Sandbox).<br />
<h3>The purpose of Import Regexp entries</h3>
They can be used for several things, such as unifying the capitalisation of file paths for more accurate event correlation or to automatically censor the usernames and use system path variable names (changing C:\Users\UserName\Appdata\Roaming\file.exe to %APPDATA%\file.exe).<br />
The second use is blocking, if a regular expression is entered with a blank replacement, any event info or attribute value containing the expression will not be added. Please make sure the entered regexp expression follows the preg_replace pattern rules as described <a href="http://php.net/manual/en/function.preg-replace.php">here</a>.<br />
<h3>Adding and modifying entries</h3>
Administrators can add, edit or delete regular expression rules, which are made up of a regex pattern that the system searches for and a replacement for the detected pattern.<br />
<p><img src="/img/doc/regexp.png" alt = "" title = "Add, edit or remove Regexp entries that will affect all newly created attributes here."/></p><br />
<hr />
<h2><a id="whitelist"></a>Managing the Signature whitelist</h2>
The signature whitelist view, accessible through the administration menu on the left, allows administrators to create and maintain a list of addresses that are whitelisted from ever being added to the NIDS signatures. Addresses listed here will be commented out when exporting the NIDS list.<br />
<h3>Whitelisting an address:</h3>
	While in the whitelist view, click on New Whitelist on the left to bring up the add whitelist view to add a new address. <br />
<h3>Managing the list:</h3>
	When viewing the list of whitelisted addresses, the following pieces of information are shown: The ID of the whitelist entry (assigned automatically when a new address is added), the address itself that is being whitelisted and a set of controls allowing you to delete the entry or edit the address.<br />
<img src="/img/doc/whitelist.png" alt = "Whitelist" title = "You can edit or delete currently white-listed addresses using the action buttons on this list."/><br />
<hr />
<h2><a id="user"></a>Managing the users:</h2>
As an admin, you can set up new accounts for users, edit the profiles of users, delete them, or just have a look at all the viewers' profiles. Organisation admins are restricted to executing the same actions on their organisation's users only.<br />
<h3>Adding a new user:</h3>
To add a new user, click on the New User button in the administration menu to the left and fill out the following fields in the view that is loaded:<br />
<img src="/img/doc/add_user.png" alt = "Add user" title = "Fill this form out to add a new user. Keep in mind that the drop-down menu titled Role controls the privileges the user will have."/>
<ul>
	<li><b>Email:</b> The user's e-mail address, this will be used as his/her login name and as an address to send all the automatic e-mails and e-mails sent by contacting the user as the reporter of an event.<br /></li>
	<li><b>Password:</b> A temporary password for the user that he/she should change after the first login. Make sure that it is at least 6 characters long, includes a digit or a special character and contains at least one upper-case and at least one lower-case character.<br /></li>
	<li><b>Confirm Password:</b> This should be an exact copy of the Password field.<br /></li>
	<li><b>Org:</b>The organisation of the user. Entering ADMIN into this field will give administrator privileges to the user. If you are an organisation admin, then this field will be unchangeable and be set to your own organisation.<br /></li>
	<li><b>Roles:</b> A drop-down list allows you to choose a role-group that the user should belong to. Roles define the privileges of the user. To learn more about roles, <a href=#roles>click here</a>.<br /></li>
	<li><b>Receive alerts when events are published:</b> This option will subscribe the new user to automatically generated e-mails whenever an event is published.<br /></li>
	<li><b>Receive alerts from "contact reporter" requests:</b> This option will subscribe the new user to e-mails that are generated when another user tries to get in touch with an event's reporting organisation that matches that of the new user.<br /></li>
	<li><b>Authkey:</b> This is assigned automatically and is the unique authentication key of the user (he/she will be able to reset this and receive a new key). It is used for exports and for connecting one server to another, but it requires the user to be assigned to a role that has auth permission enabled.<br /></li>
	<li><b>NIDS Sid:</b> Nids ID, not yet implemented.<br /></li>
	<li><b>Gpgkey:</b> The key used for encrypting e-mails sent through the system. <br /></li>
</ul>
<h3>Listing all users:</h3>
To list all current users of the system, just click on List Users under the administration menu to the left. A view will be loaded with a list of all users and the following columns of information:<br />
<img src="/img/doc/list_users.png" alt = "List users" title = "View, Edit or Delete a user using the action buttons to the right."/><br />
<ul>
	<li><b>Id:</b> The user's automatically assigned ID number.<br /></li>
	<li><b>Org:</b> The organisation that the user belongs to.<br /></li>
	<li><b>Email:</b> The e-mail address (and login name) of the user.<br /></li>
	<li><b>Autoalert:</b> Shows whether the user has subscribed to auto-alerts and is always receiving the mass-emails regarding newly published events that he/she is eligible for.<br /></li>
	<li><b>ontactalert:</b> Shows whether the user has the subscription to contact reporter e-mails directed at his/her organisation turned on or off.<br /></li>
	<li><b>Gpgkey:</b> Shows whether the user has entered a Gpgkey yet.<br /></li>
	<li><b>Nids Sid:</b> Shows the currently assigned NIDS ID.<br /></li>
	<li><b>Termsaccepted:</b> This flag indicates whether the user has accepted the terms of use or not.<br /></li>
	<li><b>Newsread:</b> The last point in time when the user has looked at the news section of the system.<br /></li>
	<li><b>Action Buttons:</b> Here you can view a detailed view of a user, edit the basic details of a user (same view as the one used for creating a new user, but all the fields come filled out by default) or remove a user completely. <br /></li>
</ul>
<h3>Editing a user:</h3>
To add a new user, click on the New User button in the administration menu to the left and fill out the following fields in the view that is loaded:<br />
<ul>
	<li><b>Email:</b> The user's e-mail address, this will be used as his/her login name and as an address to send all the automatic e-mails and e-mails sent by contacting the user as the reporter of an event.<br /></li>
	<li><b>Password:</b> It is possible to assign a new password manually for a user. For example, in case that he/she forgot the old one a new temporary one can be assigned. Make sure to check the "Change password" field if you do give out a temporary password, so that the user will be forced to change it after login.<br /></li>
	<li><b>Confirm Password:</b> This should be an exact copy of the Password field.<br /></li>
	<li><b>Org:</b>The organisation of the user. Entering ADMIN into this field will give administrator privileges to the user. If you are an organisation admin, then this field will be unchangeable and be set to your own organisation.<br /></li>
	<li><b>Roles:</b> A drop-down list allows you to choose a role-group that the user should belong to. Roles define the privileges of the user. To learn more about roles, <a href=#roles>click here</a>.<br /></li>
	<li><b>Receive alerts when events are published:</b> This option will subscribe the user to automatically generated e-mails whenever an event is published.<br /></li>
	<li><b>Receive alerts from "contact reporter" requests:</b> This option will subscribe the user to e-mails that are generated when another user tries to get in touch with an event's reporting organisation that matches that of the user.<br /></li>
	<li><b>Authkey:</b> It is possible to request a new authentication key for the user. <br /></li>
	<li><b>NIDS Sid:</b> Nids ID, not yet implemented.<br /></li>
	<li><b>Termsaccepted:</b> Indicates whether the user has accepted the terms of use already or not.<br /></li>
	<li><b>Change Password:</b> Setting this flag will require the user to change password after the next login.<br /></li>
	<li><b>Gpgkey:</b> The key used for encrypting e-mails sent through the system. <br /></li>
</ul>
<h3>Contacting a user:</h3>
Site admins can use the "Contact users" feature to send all or an individual user an e-mail. Users that have a PGP key set will receive their e-mails encrypted. When clicking this button on the left, you'll be presented with a form that allows you to specify the type of the e-mail, who it should reach and what the content is using the following options:<br />
<img src="/img/doc/contact.png" alt = "Contact" title = "Contact your users here."/><br />
<ul>
	<li><b>Action:</b> This defines the type of the e-mail, which can be a custom message or a password reset. Password resets automatically include a new temporary password at the bottom of the message and will automatically change the user's password accordingly.<br /></li>
	<li><b>Recipient:</b> The recipient toggle lets you contact all your users, a single user (which creates a second drop-down list with all the e-mail addresses of the users) and potential future users (which opens up a text field for the e-mail address and a text area field for a PGP public key).<br /></li>
	<li><b>Subject:</b> In the case of a custom e-mail, you can enter a subject line here.<br /></li>
	<li><b>Subject:</b> In the case of a custom e-mail, you can enter a subject line here.<br /></li>
	<li><b>Custom message checkbox:</b> This is available for password resets, you can either write your own message (which will be appended with a temporary key and the signature), or let the system generate one automatically.<br /></li>
</ul>
Keep in mind that all e-mails sent through this system will, in addition to your own message, will be signed in the name of the instance's host organisation's support team, will include the e-mail address of the instance's support (if the contact field is set in the bootstrap file), and will include the instance's PGP signature for users that have a PGP key set (and thus are eligible for an encrypted e-mail).
<hr />
<h2><a id="roles"></a>Managing the roles</h2>
Privileges are assigned to users by assigning them to rule groups, which use one of four options determining what they can do with events and four additional privilege elevating settings. The four options for event manipulation are: Read Only, Manage My Own Events, Manage Organisation Events, Manage &amp; Publish Organisation Events. The extra privileges are admin, sync, authentication key usage and audit permission<br />
<b>Read Only:</b> This allows the user to browse events that his organisation has access to, but doesn't allow any changes to be made to the database. <br />
<b>Manage My Own Events:</b> The second option, gives its users rights to create, modify or delete their own events, but they cannot publish them. <br />
<b>Manage Organization Events:</b> allows users to create events or modify and delete events created by a member of their organisation. <br />
<b>Manage &amp; Publish Organisation Events:</b> This last setting, gives users the right to do all of the above and also to publish the events of their organisation.<br />
<b>Perm sync:</b> This setting allows the users of the role to be used as a synchronisation user. The authentication key of this user can be handed out to the administrator of a remote MISP instance to allow the synchronisation features to work.<br />
<b>Perm auth:</b> This setting enables the authentication key of the role's users to be used for rest requests. <br />
<b>Perm admin:</b> Gives the user limited administrator privileges, this setting is used for the organisation admins. <br />
<b>Perm site admin:</b> Gives the user full administrator privileges, this setting is used for the site admins. <br />
<b>Perm audit:</b> Grants access to the logs. With the exception of site admins, only logs generated by the user's own org are visible. <br />
<b>Perm regexp access:</b> Allows the users with this permission enabled to edit the regular expression table. Be careful when giving out this permission, incorrect regular expressions can be very harmful (infinite loops, loss of data, etc.). <br />
<b>Perm tagger:</b> Allows the user with this permission to create custom tags and assign them to events. <br />
<h3>Creating roles:</h3>
When creating a new role, you will have to enter a name for the role to be created and set up the permissions (as described above) using the radio toggle and the four check-boxes.<br />
<h3>Listing roles:</h3>
By clicking on the List Roles button, you can view a list of all the currently registered roles and a list of the permission flags turned on for each. In addition, you can find buttons that allow you to edit and delete the roles. Keep in mind that you will need to first remove every member from a role before you can delete it.<br />
<img src="/img/doc/list_groups.png" alt = "List roles" title = "You can View, Edit or Delete roles using the action buttons to the right in each row. Keep in mind that a role has to be devoid of members before it can be deleted."/><br />
<hr />
<h2><a id="logs"></a>Using the logs of MISP</h2>
Users with audit permissions are able to browse or search the logs that MISP automatically appends each time certain actions are taken (actions that modify data or if a user logs in and out).<br />
Generally, the following actions are logged:<br /><br />
<ul>
<li><b>User:</b> Creation, deletion, modification, Login / Logout<br /></li>
<li><b>Event:</b>Creation, deletion, modification, publishing<br /></li>
<li><b>Attribute:</b> Creation, deletion, modification<br /></li>
<li><b>ShadowAttribute:</b> Creation, deletion, Accept, Discard<br /></li>
<li><b>Roles:</b> Creation, deletion, modification<br /></li>
<li><b>Blacklist:</b> Creation, deletion, modification<br /></li>
<li><b>Whitelist:</b> Creation, deletion, modification<br /></li>
<li><b>Regexp:</b> Creation, deletion, modification</li>
</ul>
<br />
<h3>Browsing the logs:</h3>
Listing all the log entries will show the following columns generated by the users of your organisation (or all organisations in the case of site admins):<br />
<img src="/img/doc/list_logs.png" alt = "List logs" title = "Here you can view a list of all logged actions."/><br /><br />
<ul>
	<li><b>Id:</b> The automatically assigned ID number of the entry.<br /></li>
	<li><b>Email:</b> The e-mail address of the user whose actions triggered the entry.<br /></li>
	<li><b>Org:</b> The organisation of the above mentioned user.<br /></li>
	<li><b>Created:</b> The date and time when the entry originated.<br /></li>
	<li><b>Action:</b> The action's type. This can include: login/logout for users, add, edit, delete for events, attributes, users and servers.<br /></li>
	<li><b>Title:</b> The title of an event always includes the target type (Event, User, Attribute, Server), the target's ID and the target's name (for example: e-mail address for users, event description for events).<br /></li>
	<li><b>Change:</b> This field is only filled out for entries with the action being add or edit. The changes are detailed in the following format:<br />
			<i>variable (initial_value)</i> =&gt; <i>(new_value)</i>,...<br />
			When the entry is about the creation of a new item (such as adding a new event) then the change will look like this for example:<br />
			<i>org()</i> =&gt; <i>(ADMIN)</i>, <i>date()</i> =&gt; <i>(20012-10-19)</i>,... <br />
</ul>
<img src="/img/doc/search_log.png" alt = "Search log" style="float:right;" title = "You can search the logs using this form, narrow down your search by filling out several fields."/>
<h3>Searching the Logs:</h3>
Another way to browse the logs is to search it by filtering the results according to the following fields (the search is a sub-string search, the sub-string has to be an exact match for the entry in the field that is being searched for):<br /><br />
<ul>
	<li><b>Email:</b> By searching by Email, it is possible to view the log entries of a single user.<br /></li>
	<li><b>Org:</b> Searching for an organisation allows you to see all actions taken by any member of the organisation.<br /></li>
	<li><b>Action:</b> With the help of this drop down menu, you can search for various types of actions taken (such as logins, deletions, etc).<br /></li>
	<li><b>Title:</b> There are several ways in which to use this field, since the title fields contain several bits of information and the search searches for any substrings contained within the field, it is possible to just search for the ID number of a logged event, the username / server's name / event's name / attribute's name of the event target.<br /></li>
	<li><b>Change:</b> With the help of this field, you can search for various specific changes or changes to certain variables (such as published will find all the log entries where an event has gotten published, ip-src will find all attributes where a source IP address has been entered / edited, etc).<br /></li>
</ul>
<hr />
<h2><a id="admin_tools"></a>Administrative Tools</h2>
MISP has a couple of administrative tools that help administrators keep their instance up to date and healthy. The list of these small tools can change rapidly with each new version, but they should be self-explanatory. Make sure to check this section after upgrading to a new version, just in case there is a new upgrade script in there - though if this is the case it will be mentioned in the upgrade instructions.<br /><br />
<hr />
<h2><a id="background"></a>Background Processing</h2>
If enabled, MISP can delegate a lot of the time intensive tasks to the background workers. These will then be executed in order, allowing the users of the instance to keep using the system without a hiccup and without having to wait for the process to finish. It also allows for certain tasks to be scheduled and automated.
<h3>Command Line Tools for the Background Workers</h3>
The background workers are powered by <a href="https://github.com/kamisama/Cake-Resque">CakeResque</a>, so all of the CakeResque commands work. 
To start all of the workers needed by MISP go to your <code>/var/www/MISP/app/Console/worker</code> (assuming a standard installation path) and execute start.sh.
To interact with the workers, here is a list of useful commands. Go to your <code>/var/www/MISP/app/Console</code> (assuming a standard installation path) and execute one of the following commands as a parameter to <code>./cake CakeResque.CakeResque</code> (for example: <code>./cake CakeResque.CakeResque tail</code>):<br /><br />
<ul>
<li><b>tail</b>: tail the various log files that CakeResque creates, just choose the one from the list that you are interested in.</li>
<li><b>cleanup</b>: terminate the job that a worker is working on immediately. You will be presented with a choice of workers to choose from when executing this command.</li>
<li><b>clear</b>: Clear the queue of a worker immediately.</li>
<li><b>stats</b>: shows some statistics about your workers including the count of successful and failed jobs.</li>
</ul>
The other commands should not be needed, instead of starting / stopping or restarting workers use the supplied start.sh (it stops all workers and starts them all up again). For further instructions on how to use the console commands for the workers, visit the <a href="http://cakeresque.kamisama.me/commands#cleanup">CakeResque list of commands</a>.<br />
<h3>Monitoring the Background Processes</h3>
The "Jobs" menu item within the Administration menu allows site admins to get an overview of all of the currently and in the past scheduled jobs. Admins can see the status of each job, and what the queued job is trying to do. If a job fails, it will try to set an error message here too. The following columns are shown in the jobs table:<br /><br />
<ul>
<li><b>Id</b>: The job's ID (this is the ID of the job's metadata stored in the default datastore, not to be confused with the process ID stored in the redis database and used by the workers)</li>
<li><b>Process</b>: The process's ID.</li>
<li><b>Worker</b>: The name of the worker queue. There are 3+1 workers running if background jobs are enabled: default, cache, email, and a special Scheduler (this should never show up in the jobs table).</li>
<li><b>Job Type</b>: The name of the queued job.</li>
<li><b>Input</b>: Shows a basic input handled by the job - such as "Event:50" for a publish email alert job for event 50.</li>
<li><b>Message</b>: This will show what the job is currently doing or alternatively an error message describing why a job failed. </li>
<li><b>Org</b>: The string identifier of the organisation that has scheduled the job. </li>
<li><b>Status</b>: The status reported by the worker.</li>
<li><b>Retries</b>: Currently unused, it is planned to introduced automatic delayed retries for the background processing to add resilience.</li>
<li><b>Progress</b>: A progress bar showing how the job is coming along.</li>
</ul>
<br /><img src="/img/doc/jobs.png" alt = "" title = "Site administrators can monitor the process of all queued jobs here."/><br />
<h3>Scheduling Jobs and Recurring Jobs</h3>
Apart from off-loading long-lasting jobs to the background workers, there is a second major benefit of enabling the background workers: Site-administrators can schedule recurring tasks for the jobs that generally take the longest to execute. At the moment this includes pushing / pulling other instances and generating a full export cache for every organisation and export type. MISP comes with these 3 tasks pre-defined, but further tasks are planned. The following fields make up the scheduled tasks table: <br /><br />
<ul>
<li><b>Id</b>: The ID of the task.</li>
<li><b>Type</b>: The type of the task.</li>
<li><b>Frequency (h)</b>: This number sets how often the job should be executed in hours. Setting this to 168 and picking the next execution on Sunday at 01:00 would execute the task every Sunday at 1 AM. Setting this value to 0 will make the task only run once on the scheduled date / time without rescheduling it afterwards.</li>
<li><b>Scheduled Time</b>: The time (in 24h format) when the task should be executed the next time it runs (and all consecutive times if a multiple of 24 is chosen for frequency).</li>
<li><b>Next Run</b>: The date on which the task should be executed.</li>
<li><b>Description</b>: A brief description of the task.</li>
<li><b>Message</b>: This field shows when the job was queued by the scheduler for execution. </li><br />
</ul>
<br /><img src="/img/doc/schedule.png" alt = "" title = "Site administrators can schedule reccuring tasks on this page."/><br />
</div>