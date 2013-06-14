<div class="actions" style="width:15%">
	<ol class="nav nav-list">
		<li><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'documentation')); ?></li>
		<li><?php echo $this->Html->link('General Concepts', array('controller' => 'pages', 'action' => 'display', 'concepts')); ?></li>
		<li><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'user_management')); ?></li>
		<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'using_the_system')); ?></li>
		<li class="active"><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'administration')); ?>
			<ul class="nav nav-list">
				<li><a href="#blacklist">Blacklist</a></li>
				<li><a href="#regexp">Import Regexp</a></li>
				<li><a href="#whitelist">Signature Whitelist</a></li>
				<li><a href="#user">User Management</a></li>
				<li><a href="#roles">Role Management</a></li>
				<li><a href="#logs">Logging</a></li>
			</ul>
		</li>
		<li><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?></li>
	</ol>
</div>

<div class="index" style="width:80%">
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
	<li><em>Email:</em> The user's e-mail address, this will be used as his/her login name and as an address to send all the automatic e-mails and e-mails sent by contacting the user as the reporter of an event.<br /></li>
	<li><em>Password:</em> A temporary password for the user that he/she should change after the first login. Make sure that it is at least 6 characters long, includes a digit or a special character and contains at least one upper-case and at least one lower-case character.<br /></li>
	<li><em>Confirm Password:</em> This should be an exact copy of the Password field.<br /></li>
	<li><em>Org:</em>The organisation of the user. Entering ADMIN into this field will give administrator privileges to the user. If you are an organisation admin, then this field will be unchangeable and be set to your own organisation.<br /></li>
	<li><em>Roles:</em> A drop-down list allows you to choose a role-group that the user should belong to. Roles define the privileges of the user. To learn more about roles, <a href=#roles>click here</a>.<br /></li>
	<li><em>Receive alerts when events are published:</em> This option will subscribe the new user to automatically generated e-mails whenever an event is published.<br /></li>
	<li><em>Receive alerts from "contact reporter" requests:</em> This option will subscribe the new user to e-mails that are generated when another user tries to get in touch with an event's reporting organisation that matches that of the new user.<br /></li>
	<li><em>Authkey:</em> This is assigned automatically and is the unique authentication key of the user (he/she will be able to reset this and receive a new key). It is used for exports and for connecting one server to another, but it requires the user to be assigned to a role that has auth permission enabled.<br /></li>
	<li><em>NIDS Sid:</em> Nids ID, not yet implemented.<br /></li>
	<li><em>Gpgkey:</em> The key used for encrypting e-mails sent through the system. <br /></li>
</ul>
<h3>Listing all users:</h3>
To list all current users of the system, just click on List Users under the administration menu to the left. A view will be loaded with a list of all users and the following columns of information:<br />
<img src="/img/doc/list_users.png" alt = "List users" title = "View, Edit or Delete a user using the action buttons to the right."/><br />
<ul>
	<li><em>Id:</em> The user's automatically assigned ID number.<br /></li>
	<li><em>Org:</em> The organisation that the user belongs to.<br /></li>
	<li><em>Email:</em> The e-mail address (and login name) of the user.<br /></li>
	<li><em>Autoalert:</em> Shows whether the user has subscribed to auto-alerts and is always receiving the mass-emails regarding newly published events that he/she is eligible for.<br /></li>
	<li><em>ontactalert:</em> Shows whether the user has the subscription to contact reporter e-mails directed at his/her organisation turned on or off.<br /></li>
	<li><em>Gpgkey:</em> Shows whether the user has entered a Gpgkey yet.<br /></li>
	<li><em>Nids Sid:</em> Shows the currently assigned NIDS ID.<br /></li>
	<li><em>Termsaccepted:</em> This flag indicates whether the user has accepted the terms of use or not.<br /></li>
	<li><em>Newsread:</em> The last point in time when the user has looked at the news section of the system.<br /></li>
	<li><em>Action Buttons:</em> Here you can view a detailed view of a user, edit the basic details of a user (same view as the one used for creating a new user, but all the fields come filled out by default) or remove a user completely. <br /></li>
</ul>
<h3>Editing a user:</h3>
To add a new user, click on the New User button in the administration menu to the left and fill out the following fields in the view that is loaded:<br />
<ul>
	<li><em>Email:</em> The user's e-mail address, this will be used as his/her login name and as an address to send all the automatic e-mails and e-mails sent by contacting the user as the reporter of an event.<br /></li>
	<li><em>Password:</em> It is possible to assign a new password manually for a user. For example, in case that he/she forgot the old one a new temporary one can be assigned. Make sure to check the "Change password" field if you do give out a temporary password, so that the user will be forced to change it after login.<br /></li>
	<li><em>Confirm Password:</em> This should be an exact copy of the Password field.<br /></li>
	<li><em>Org:</em>The organisation of the user. Entering ADMIN into this field will give administrator privileges to the user. If you are an organisation admin, then this field will be unchangeable and be set to your own organisation.<br /></li>
	<li><em>Roles:</em> A drop-down list allows you to choose a role-group that the user should belong to. Roles define the privileges of the user. To learn more about roles, <a href=#roles>click here</a>.<br /></li>
	<li><em>Receive alerts when events are published:</em> This option will subscribe the user to automatically generated e-mails whenever an event is published.<br /></li>
	<li><em>Receive alerts from "contact reporter" requests:</em> This option will subscribe the user to e-mails that are generated when another user tries to get in touch with an event's reporting organisation that matches that of the user.<br /></li>
	<li><em>Authkey:</em> It is possible to request a new authentication key for the user. <br /></li>
	<li><em>NIDS Sid:</em> Nids ID, not yet implemented.<br /></li>
	<li><em>Termsaccepted:</em> Indicates whether the user has accepted the terms of use already or not.<br /></li>
	<li><em>Change Password:</em> Setting this flag will require the user to change password after the next login.<br /></li>
	<li><em>Gpgkey:</em> The key used for encrypting e-mails sent through the system. <br /></li>
</ul>
<h3>Contacting a user:</h3>
Site admins can use the "Contact users" feature to send all or an individual user an e-mail. Users that have a PGP key set will receive their e-mails encrypted. When clicking this button on the left, you'll be presented with a form that allows you to specify the type of the e-mail, who it should reach and what the content is using the following options:<br />
<img src="/img/doc/contact.png" alt = "Contact" title = "Contact your users here."/><br />
<ul>
	<li><em>Action:</em> This defines the type of the e-mail, which can be a custom message or a password reset. Password resets automatically include a new temporary password at the bottom of the message and will automatically change the user's password accordingly.<br /></li>
	<li><em>Recipient:</em> The recipient toggle lets you contact all your users, a single user (which creates a second drop-down list with all the e-mail addresses of the users) and potential future users (which opens up a text field for the e-mail address and a text area field for a PGP public key).<br /></li>
	<li><em>Subject:</em> In the case of a custom e-mail, you can enter a subject line here.<br /></li>
	<li><em>Subject:</em> In the case of a custom e-mail, you can enter a subject line here.<br /></li>
	<li><em>Custom message checkbox:</em> This is available for password resets, you can either write your own message (which will be appended with a temporary key and the signature), or let the system generate one automatically.<br /></li>
</ul>
Keep in mind that all e-mails sent through this system will, in addition to your own message, will be signed in the name of the instance's host organisation's support team, will include the e-mail address of the instance's support (if the contact field is set in the bootstrap file), and will include the instance's PGP signature for users that have a PGP key set (and thus are eligible for an encrypted e-mail).
<hr />
<h2><a id="roles"></a>Managing the roles</h2>
Privileges are assigned to users by assigning them to rule groups, which use one of four options determining what they can do with events and four additional privilege elevating settings. The four options for event manipulation are: Read Only, Manage My Own Events, Manage Organisation Events, Manage &amp; Publish Organisation Events. The extra privileges are admin, sync, authentication key usage and audit permission<br />
<em>Read Only:</em> This allows the user to browse events that his organisation has access to, but doesn't allow any changes to be made to the database. <br />
<em>Manage My Own Events:</em> The second option, gives its users rights to create, modify or delete their own events, but they cannot publish them. <br />
<em>Manage Organization Events:</em> allows users to create events or modify and delete events created by a member of their organisation. <br />
<em>Manage &amp; Publish Organisation Events:</em> This last setting, gives users the right to do all of the above and also to publish the events of their organisation.<br />
<em>Perm sync:</em> This setting allows the users of the role to be used as a synchronisation user. The authentication key of this user can be handed out to the administrator of a remote MISP instance to allow the synchronisation features to work.<br />
<em>Perm admin:</em> Gives the user administrator privileges, this setting is used for the organisation admins. <br />
<em>Perm audit:</em> Grants access to the logs. With the exception of site admins, only logs generated by the user's own org are visible. <br />
<em>Perm auth:</em> This setting enables the authentication key of the role's users to be used for rest requests. <br />
<h3>Creating roles:</h3>
When creating a new role, you will have to enter a name for the role to be created and set up the permissions (as described above) using the radio toggle and the four check-boxes.<br />
<h3>Listing roles:</h3>
By clicking on the List Roles button, you can view a list of all the currently registered roles and a list of the permission flags turned on for each. In addition, you can find buttons that allow you to edit and delete the roles. Keep in mind that you will need to first remove every member from a role before you can delete it.<br />
<img src="/img/doc/list_groups.png" alt = "List roles" title = "You can View, Edit or Delete roles using the action buttons to the right in each row. Keep in mind that a role has to be devoid of members before it can be deleted."/><br />
<hr />
<h2><a id="logs"></a>Using the logs of MISP</h2>
Users with audit permissions are able to browse or search the logs that MISP automatically appends each time certain actions are taken (actions that modify data or if a user logs in and out).<br />
Generally, the following actions are logged:<br />
<ul>
<li><em>User:</em> Creation, deletion, modification, Login / Logout<br /></li>
<li><em>Event:</em>Creation, deletion, modification, publishing<br /></li>
<li><em>Attribute:</em> Creation, deletion, modification<br /></li>
<li><em>Roles:</em> Creation, deletion, modification<br /></li>
<li><em>Blacklist:</em> Creation, deletion, modification<br /></li>
<li><em>Whitelist:</em> Creation, deletion, modification<br /></li>
<li><em>Regexp:</em> Creation, deletion, modification</li>
</ul>
<br />
<h3>Browsing the logs:</h3>
Listing all the log entries will show the following columns generated by the users of your organisation (or all organisations in the case of site admins):<br />
<img src="/img/doc/list_logs.png" alt = "List logs" title = "Here you can view a list of all logged actions."/><br />
<ul>
	<li><em>Id:</em> The automatically assigned ID number of the entry.<br /></li>
	<li><em>Email:</em> The e-mail address of the user whose actions triggered the entry.<br /></li>
	<li><em>Org:</em> The organisation of the above mentioned user.<br /></li>
	<li><em>Created:</em> The date and time when the entry originated.<br /></li>
	<li><em>Action:</em> The action's type. This can include: login/logout for users, add, edit, delete for events, attributes, users and servers.<br /></li>
	<li><em>Title:</em> The title of an event always includes the target type (Event, User, Attribute, Server), the target's ID and the target's name (for example: e-mail address for users, event description for events).<br /></li>
	<li><em>Change:</em> This field is only filled out for entries with the action being add or edit. The changes are detailed in the following format:<br />
			<i>variable (initial_value)</i> =&gt; <i>(new_value)</i>,...<br />
			When the entry is about the creation of a new item (such as adding a new event) then the change will look like this for example:<br />
			<i>org()</i> =&gt; <i>(ADMIN)</i>, <i>date()</i> =&gt; <i>(20012-10-19)</i>,... <br />
</ul>
<img src="/img/doc/search_log.png" alt = "Search log" style="float:right;" title = "You can search the logs using this form, narrow down your search by filling out several fields."/>
<h3>Searching the Logs:</h3>
Another way to browse the logs is to search it by filtering the results according to the following fields (the search is a sub-string search, the sub-string has to be an exact match for the entry in the field that is being searched for):<br />
<ul>
	<li><em>Email:</em> By searching by Email, it is possible to view the log entries of a single user.<br /></li>
	<li><em>Org:</em> Searching for an organisation allows you to see all actions taken by any member of the organisation.<br /></li>
	<li><em>Action:</em> With the help of this drop down menu, you can search for various types of actions taken (such as logins, deletions, etc).<br /></li>
	<li><em>Title:</em> There are several ways in which to use this field, since the title fields contain several bits of information and the search searches for any substrings contained within the field, it is possible to just search for the ID number of a logged event, the username / server's name / event's name / attribute's name of the event target.<br /></li>
	<li><em>Change:</em> With the help of this field, you can search for various specific changes or changes to certain variables (such as published will find all the log entries where an event has gotten published, ip-src will find all attributes where a source IP address has been entered / edited, etc).<br /></li>
</ul>

</div>