<div class="actions" style="width:15%">
	<ol class="nav nav-list">
		<li class="active"><?php echo $this->Html->link('General Layout', array('controller' => 'pages', 'action' => 'display', 'documentation')); ?></li>
		<li><?php echo $this->Html->link('General Concepts', array('controller' => 'pages', 'action' => 'display', 'concepts')); ?></li>
		<li><?php echo $this->Html->link('User Management and Global actions', array('controller' => 'pages', 'action' => 'display', 'user_management')); ?></li>
		<li><?php echo $this->Html->link('Using the system', array('controller' => 'pages', 'action' => 'display', 'using_the_system')); ?></li>
		<li><?php echo $this->Html->link('Administration', array('controller' => 'pages', 'action' => 'display', 'administration')); ?></li>
		<li><?php echo $this->Html->link('Categories and Types', array('controller' => 'pages', 'action' => 'display', 'categories_and_types')); ?></li>
	</ol>
</div>

<div class="index" style="width:80%">
<h2>General Layout</h2>
<h3>The top bar</h3>
	<p>This menu contains all of the main functions of the site as a series of dropdown menues. These contains all (from the current user's perspective) accessible functions sorted into several groups.</p>
	<p><img src="/img/doc/menu_image.png" alt = "" style="float:right;" title = "This is the main menu that will be accessible from all of the views. In some instances, some additional buttons that will appear on top of these when a view provides it."/></p>
	<ul>
		<li><b>Home button:</b> This button will return you to the start screen of the application, which is the event index page (more about this later).</li>
		<li><b>Event Actions:</b> All the malware data entered into MISP is made up of an event object that is described by its connected attributes. The Event actions menu gives access to all the functionality that has to do with the creation, modification, deletion, publishing, searching and listing of events and attributes.</li>
		<li><b>Input Filters:</b> Input filters alter what and how data can be entered into this instance. Apart from the basic validation of attribute entry by type, it is possible for the site administrators to define regular expression replacements and blacklists for certain values in addition to blocking certain values from being exportable. Users can view these replacement and blacklist rules here whilst administrator can alter them.</li>
		<li><b>Global Actions:</b> This menu gives you access to information about MISP and this instance. You can view and edit your own profile, view the manual, read the news or the terms of use again, see a list of the active organisations on this instance and a histogram of their contributions by attribute type.</li>
		<li><b>Sync Actions:</b> With administrator access rights, shows a list of the connected instances and allows the initiation of a push and a pull (more about the synchronisation mechanisms later).</li>
		<li><b>Administrations:</b> Administrators can add, edit or remove user accounts and user roles. Roles define the access rights to certain features such as publishing of events, usage of the REST interface or synchronisation of any user belonging to the given role. Site administrators can also access a contact form, through which it is possible to reset the passwords of users, or to just get in touch with them via encrypted e-mails.</li>
		<li><b>Audit:</b> If you have audit permissions, you can view the logs for your organisation (or for site admins for the entire system) here or even search the logs if you are interested in something specific.</li>
		<li><b>Log out:</b> Logs you out of the system.</li>
	</ul>

<h3>A list of the contents of each of the above drop-down menues</h3>
	<h5>Event actions</h5>
	<ul>
		<li><b>List Events:</b> Lists all the events in the system that are not private or belong to your organisation. You can add, modify, delete, publish or view individual events from this view.</li>
		<li><b>Add Event:</b> Allows you to fill out an event creation form and create the event object, which you can start populating with attributes.</li>
		<li><b>List Attributes:</b> Lists all the attributes in the system that are not private or belong to your organisation. You can modify, delete or view each individual attribute from this view.</li>
		<li><b>Search Attributes:</b> You can set search terms for a filtered attribute index view here.</li>
		<li><b>Export:</b> Export the data accessible to you in various formats.</li>
		<li><b>Automation:</b> If you have authentication key access, you can view how to use your key to use the REST interface for automation here.</li>
	</ul>

	<h5>Input filters</h5>
	<ul>
		<li><b>Import Blacklist:</b> You can view the blacklist rules, which contain the values that are blocked from being entered as attribute values on this instance. As a site administrator you can also alter these rules.</li>
		<li><b>Import Whitelist:</b> You can view the whitelist rules, which contain the values that are blocked from being used for exports and automation on this instance. As a site administrator you can also alter these rules.</li>
		<li><b>Import Regexp:</b> You can view the Regular Expression rules, which modify the data that can be entered into the system. This can and should be used to help filter out personal information from automatic imports (such as removing the username from windows file paths), having unified representation for certain common values for easier correlation or simply standardising certain input. As a site administrator you can also edit these rules.</li>
	</ul>

	<h5>Global Actions</h5>
	<ul>
		<li><b>News:</b> Read about the latest news regarding the MISP system</li>
		<li><b>My Profile:</b> Manage your user account.</li>
		<li><b>Members List:</b> View the number of users per organisation and get some statistics about the currently stored attributes.</li>
		<li><b>User Guide:</b> A link to this user guide.</li>
		<li><b>Terms &amp; Conditions:</b> View the terms &amp; conditions again.</li>
		<li><b>Log out:</b> Logs the current user out.</li>
	</ul>

	<h5>Sync Actions</h5>
	<ul>
		<li><em>List Servers:</em> Connect your MISP instance to other instances, or view and modify the currently established connections.</li>
	</ul>

	<h5>Administration</h5>
	<ul>
		<li><em>New User:</em> Create an account for a new user for your organisation. Site administrators can create users for any organisation.</li>
		<li><em>List Users:</em> View, modify or delete the currently registered users.</li>
		<li><em>New Role:</em> Create a new role group for the users of this instance, controlling their privileges to create, modify, delete and to publish events and to access certain features such as the logs or automation.</li>
		<li><em>List Roles:</em> List, modify or delete currently existing roles.</li>
		<li><em>Contact Users:</em> You can use this view to send messages to your current or future users or send them a new temporary password.</li>
	</ul>

	<h5>Audit</h5>
	<ul>
		<li><em>List Logs:</em> View the logs of the instance.</li>
		<li><em>Search Logs:</em> Search the logs by various attributes.</li>
	</ul>
<h3>The left bar</h3>
	<p>This bar changes based on each page-group. The blue selection shows you what page you are on.</p>
</div>
